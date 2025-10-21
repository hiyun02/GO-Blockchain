package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/syndtr/goleveldb/leveldb"
)

////////////////////////////////////////////////////////////////////////////////
// LevelDB Storage (CP 하부체인용)
// ----------------------------------------------------------------------------
// - 블록 타입은 LowerBlock (PoW/Nonce 없음, cp_id 포함)
// - 블록 저장: 번호/해시 두 축으로 JSON 저장
// - 콘텐츠 색인: cid/fp/info 기반 → "<blockIndex>:<entryIndex>" 포인터 저장
//   (이전처럼 block_hash만 저장하면 재시작 후 entry 위치를 다시 스캔해야 해서 비효율)
// - 추가 메타: 최신 루트 캐시 등은 선택
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

// initDB : LevelDB 열기 (main.go에서 호출)
func initDB(path string) {
	var err error
	db, err = leveldb.OpenFile(path, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[DB] LevelDB initialized at", path)
}

// closeDB : LevelDB 닫기 (main.go 종료 시 호출)
func closeDB() {
	if db != nil {
		db.Close()
		log.Println("[DB] Closed LevelDB")
	}
}

////////////////////////////////////////////////////////////////////////////////
// 블록 저장/조회
////////////////////////////////////////////////////////////////////////////////

// saveBlockToDB : LowerBlock 전체를 JSON으로 저장
// - Key1: "block_<Index>"     => LowerBlock JSON (번호 기반 접근)
// - Key2: "hash_<BlockHash>"  => LowerBlock JSON (해시 기반 접근)
// 주: 키 형식은 기존 코드와의 호환을 위해 유지
func saveBlockToDB(block LowerBlock) error {
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
	return nil
}

// 인덱스로 블록 조회
func getBlockByIndex(index int) (LowerBlock, error) {
	key := fmt.Sprintf("block_%d", index)
	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return LowerBlock{}, err
	}
	var block LowerBlock
	if err := json.Unmarshal(data, &block); err != nil {
		return LowerBlock{}, err
	}
	return block, nil
}

// 블록 해시로 조회
func getBlockByHash(hash string) (LowerBlock, error) {
	key := fmt.Sprintf("hash_%s", hash)
	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return LowerBlock{}, err
	}
	var block LowerBlock
	if err := json.Unmarshal(data, &block); err != nil {
		return LowerBlock{}, err
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

////////////////////////////////////////////////////////////////////////////////
// 해시테이블(검색 인덱스) 업데이트
//  - 블록 단위로 cid/fp/info 색인을 "<blockIndex>:<entryIndex>" 포인터로 저장
////////////////////////////////////////////////////////////////////////////////

func updateIndicesForBlock(block LowerBlock) error {
	// 포인터 문자열: "blockIndex:entryIndex"
	ptr := func(bi, ei int) []byte { return []byte(fmt.Sprintf("%d:%d", bi, ei)) }

	for ei, entry := range block.Entries {
		// 1) ContentID 색인: "cid_<ContentID>" -> "bi:ei"
		if entry.ContentID != "" {
			keyByCID := fmt.Sprintf("cid_%s", entry.ContentID)
			if err := db.Put([]byte(keyByCID), ptr(block.Index, ei), nil); err != nil {
				return err
			}
		}

		// 2) Fingerprint 색인: "fp_<Fingerprint>" -> "bi:ei"
		if entry.Fingerprint != "" {
			keyByFP := fmt.Sprintf("fp_%s", entry.Fingerprint)
			if err := db.Put([]byte(keyByFP), ptr(block.Index, ei), nil); err != nil {
				return err
			}
		}

		// 3) Info 키워드 색인(간단 버전)
		//    - 점 표기(dotted key)나 부분일치는 API 레이어에서 확장 가능
		//    - 여기서는 title 같은 문자열을 소문자로 normalize해서 저장
		for k, v := range entry.Info {
			strVal := strings.TrimSpace(fmt.Sprintf("%v", v))
			if strVal == "" {
				continue
			}
			key := fmt.Sprintf("info_%s_%s", k, strings.ToLower(strVal))
			if err := db.Put([]byte(key), ptr(block.Index, ei), nil); err != nil {
				return err
			}
		}
	}

	log.Printf("[DB] Indices updated for Block #%d (%d entries)\n",
		block.Index, len(block.Entries))
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// 검색 유틸
////////////////////////////////////////////////////////////////////////////////

// parsePtr : "bi:ei" → (bi, ei, ok)
func parsePtr(s string) (int, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	bi, err1 := strconv.Atoi(parts[0])
	ei, err2 := strconv.Atoi(parts[1])
	return bi, ei, err1 == nil && err2 == nil
}

// getBlockByContent : 키워드로 블록 조회(단순 버전)
//   - keyword가 ContentID, Fingerprint, 또는 Info(title 등)에 매칭되면
//     해당 포인터("bi:ei")를 통해 블록을 찾아 반환
//   - 여러 매칭이 가능할 수 있으나, 여기서는 최초 매칭 1개만 반환(간단화)
func getBlockByContent(keyword string) (LowerBlock, error) {
	// ContentID 색인 조회
	if v, err := db.Get([]byte("cid_"+keyword), nil); err == nil {
		if bi, _, ok := parsePtr(string(v)); ok {
			return getBlockByIndex(bi)
		}
	}

	// Fingerprint 색인 조회
	if v, err := db.Get([]byte("fp_"+keyword), nil); err == nil {
		if bi, _, ok := parsePtr(string(v)); ok {
			return getBlockByIndex(bi)
		}
	}

	// Info(title 등) 색인 조회 (소문자 normalize)
	if v, err := db.Get([]byte("info_title_"+strings.ToLower(keyword)), nil); err == nil {
		if bi, _, ok := parsePtr(string(v)); ok {
			return getBlockByIndex(bi)
		}
	}

	return LowerBlock{}, fmt.Errorf("no block found for keyword: %s", keyword)
}

// ==========================
// 전체 장부(블록) 조회 유틸
// ==========================

// 전체 블록 조회
func listAllBlocks() ([]LowerBlock, error) {
	h, ok := getLatestHeight()
	if !ok {
		// 제네시스만 있을 수도 있으니 0만 확인
		b0, err := getBlockByIndex(0)
		if err != nil {
			return nil, fmt.Errorf("no chain: %w", err)
		}
		return []LowerBlock{b0}, nil
	}
	out := make([]LowerBlock, 0, h+1)
	for i := 0; i <= h; i++ {
		b, err := getBlockByIndex(i)
		if err != nil {
			return nil, fmt.Errorf("load block_%d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// ListBlocksPaginated : offset에서 최대 limit개 반환, total(=height+1)도 함께 반환
func listBlocksPaginated(offset, limit int) ([]LowerBlock, int, error) {
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
		return []LowerBlock{}, total, nil
	}
	end := offset + limit - 1
	if end > h {
		end = h
	}
	out := make([]LowerBlock, 0, end-offset+1)
	for i := offset; i <= end; i++ {
		b, err := getBlockByIndex(i)
		if err != nil {
			return nil, total, fmt.Errorf("load block_%d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, total, nil
}
