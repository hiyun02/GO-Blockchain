package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

////////////////////////////////////////////////////////////////////////////////
// LevelDB Storage for OTT Chain
// ----------------------------------------------------------------------------
// - UpperBlock 저장: 번호/해시 두 축으로 JSON 저장
// - AnchorRecord는 개별 콘텐츠가 아닌 CP 체인 루트 정보이므로
// - OTT 체인은 계약 및 앵커 단위 데이터 검증만 수행하므로,
//   검색 인덱스 대신 블록 단위 조회 및 루트 캐시 위주로 구성
////////////////////////////////////////////////////////////////////////////////

// 전역 DB 핸들 (단일 프로세스 내에서 공유)
var db *leveldb.DB

// ---- 내부 메타키 헬퍼 ---------------------------------------------------------
func putMeta(key, val string) error {
	return db.Put([]byte(key), []byte(val), nil)
}
func getMeta(key string) (string, bool) {
	v, err := db.Get([]byte(key), nil)
	if err != nil {
		return "", false
	}
	return string(v), true
}

func getLatestHeight() (int, bool) {
	if s, ok := getMeta("height_latest"); ok {
		h, err := strconv.Atoi(s)
		if err == nil {
			return h, true
		}
	}
	return 0, false
}
func setLatestHeight(h int) error {
	return putMeta("height_latest", strconv.Itoa(h))
}

// DB 초기화
func initDB(path string) {
	var err error
	db, err = leveldb.OpenFile(path, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[DB][OTT] LevelDB initialized at", path)
}

// DB 종료
func closeDB() {
	if db != nil {
		db.Close()
		log.Println("[DB][OTT] Closed LevelDB")
	}
}

////////////////////////////////////////////////////////////////////////////////
// 블록 저장/조회
////////////////////////////////////////////////////////////////////////////////

// UpperBlock 전체를 JSON으로 저장
// - Key1: "block_<Index>"     => UpperBlock JSON (번호 기반 접근)
// - Key2: "hash_<BlockHash>"  => UpperBlock JSON (해시 기반 접근)
// 주: 키 형식은 기존 코드와의 호환을 위해 유지
func saveBlockToDB(block UpperBlock) error {
	data, err := json.Marshal(block)
	if err != nil {
		return err
	}

	// 블록 번호 기반 저장
	keyByIndex := fmt.Sprintf("block_%d", block.Index)
	if err := db.Put([]byte(keyByIndex), data, nil); err != nil {
		return err
	}

	// 블록 해시 기반 저장
	keyByHash := fmt.Sprintf("hash_%s", block.BlockHash)
	if err := db.Put([]byte(keyByHash), data, nil); err != nil {
		return err
	}

	// 최신 루트 캐시(선택)
	if err := db.Put([]byte("root_latest"), []byte(block.MerkleRoot), nil); err != nil {
		return err
	}

	log.Printf("[DB] Block #%d saved (Hash=%s)\n", block.Index, block.BlockHash)
	appendBlockLog(block)
	return nil
}

// 인덱스로 블록 조회
func getBlockByIndex(index int) (UpperBlock, error) {
	key := fmt.Sprintf("block_%d", index)
	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return UpperBlock{}, err
	}
	var block UpperBlock
	if err := json.Unmarshal(data, &block); err != nil {
		return UpperBlock{}, err
	}
	return block, nil
}

// 블록 해시로 조회
func getBlockByHash(hash string) (UpperBlock, error) {
	key := fmt.Sprintf("hash_%s", hash)
	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return UpperBlock{}, err
	}
	var block UpperBlock
	if err := json.Unmarshal(data, &block); err != nil {
		return UpperBlock{}, err
	}
	return block, nil
}

// 최신 루트 캐시 조회(없으면 빈 문자열)
func getLatestRoot() string {
	if v, err := db.Get([]byte("root_latest"), nil); err == nil {
		return string(v)
	}
	return ""
}

// UpperBlock 내의 AnchorRecord(각 CP별 앵커 데이터)를 기반으로
// LevelDB에 색인 정보를 갱신하는 함수
func updateIndicesForBlock(block UpperBlock) error {
	ptr := func(bi, ei int) []byte { return []byte(fmt.Sprintf("%d:%d", bi, ei)) }

	for ei, rec := range block.Records {
		// CP별 앵커 색인 등록
		if rec.CPID != "" {
			keyByCP := fmt.Sprintf("anchor_%s", rec.CPID)
			if err := db.Put([]byte(keyByCP), ptr(block.Index, ei), nil); err != nil {
				return err
			}
		}
	}

	log.Printf("[DB] Indices updated for UpperBlock #%d (%d anchors)\n",
		block.Index, len(block.Records))
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// 검색 유틸
////////////////////////////////////////////////////////////////////////////////

// parsePtr : "bi:ei" => (bi, ei, ok)
func parsePtr(s string) (int, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	bi, err1 := strconv.Atoi(parts[0])
	ei, err2 := strconv.Atoi(parts[1])
	return bi, ei, err1 == nil && err2 == nil
}

// ==========================
// 전체 장부(블록) 조회 유틸
// ==========================

// 전체 블록 조회
func listAllBlocks() ([]UpperBlock, error) {
	h, ok := getLatestHeight()
	if !ok {
		// 제네시스만 있을 수도 있으니 0만 확인
		b0, err := getBlockByIndex(0)
		if err != nil {
			return nil, fmt.Errorf("no chain: %w", err)
		}
		return []UpperBlock{b0}, nil
	}
	out := make([]UpperBlock, 0, h+1)
	for i := 0; i <= h; i++ {
		b, err := getBlockByIndex(i)
		if err != nil {
			return nil, fmt.Errorf("load block_%d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// 페이지네이션 조회 : ffset에서 최대 limit개 반환, total(=height+1)도 함께 반환
func listBlocksPaginated(offset, limit int) ([]UpperBlock, int, error) {
	if offset < 0 || limit <= 0 {
		return nil, 0, fmt.Errorf("invalid offset/limit")
	}
	h, ok := getLatestHeight()
	if !ok {
		// 제네시스만 있는지 확인
		if _, err := getBlockByIndex(0); err != nil {
			return nil, 0, fmt.Errorf("no chain: %w", err)
		}
		h = 0
	}
	total := h + 1
	if offset >= total {
		return []UpperBlock{}, total, nil
	}
	end := offset + limit - 1
	if end > h {
		end = h
	}
	out := make([]UpperBlock, 0, end-offset+1)
	for i := offset; i <= end; i++ {
		b, err := getBlockByIndex(i)
		if err != nil {
			return nil, total, fmt.Errorf("load block_%d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, total, nil
}

// 현재 노드의 CP 식별자 반환 (메타데이터에서 읽기)
func selfID() string {
	if v, ok := getMeta("meta_ott_id"); ok {
		return v
	}
	return "UNKNOWN_OTT"
}

func appendBlockLog(block UpperBlock) {
	f, err := os.OpenFile("block_history.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[LOG][ERROR] cannot open blockHistory file: %v", err)
		return
	}
	defer f.Close()
	// txt 파일에 저장할 내용
	line := fmt.Sprintf("Block #%02d, Entries : %04d, EndStamp : %s, Difficulty : %d \n",
		block.Index, len(block.Records), time.Unix(time.Now().Unix(), 0).Format(time.RFC3339), block.Difficulty)

	if _, err := f.WriteString(line); err != nil {
		log.Printf("[LOG][ERROR] cannot write blockHistory: %v", err)
	}
	log.Printf("[LOG][WRITE] Success to Write BlockHistory: %v", err)
}

// 로컬 체인을 완전히 초기화하고 제네시스 블록만 재생성
func resetLocalDB() error {
	chainMu.Lock()
	defer chainMu.Unlock()

	log.Printf("[CHAIN] Local chain RESET in progress...")

	// LevelDB 전체 삭제
	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		if err := db.Delete(key, nil); err != nil {
			iter.Release()
			return fmt.Errorf("failed to delete key %s: %v", string(key), err)
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error during db clear: %v", err)
	}

	// 로컬 height 초기화
	if err := setLatestHeight(-1); err != nil {
		return fmt.Errorf("failed to reset height: %v", err)
	}

	log.Printf("[CHAIN] Local chain RESET complete ")
	return nil
}
