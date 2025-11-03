package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// PoW (Proof of Work) 모듈
// ------------------------------------------------------------
// - 모든 노드가 동시에 PoW 연산 수행
// - 가장 먼저 조건을 만족한 노드가 블록 브로드캐스트
// - 다른 노드는 즉시 채굴 중단 => 검증 => 체인에 추가
////////////////////////////////////////////////////////////////////////////////

// 난이도: 전역 상수 (모든 노드 동일)
const GlobalDifficulty = 4 // "0000"으로 시작해야 유효

// 채굴 중단 플래그 (다른 노드가 성공 시 true)
var miningStop atomic.Bool

// 작업증명 시 해시 대상 헤더 정보
type PoWHeader struct {
	Index      int    `json:"index"`
	PrevHash   string `json:"prev_hash"`
	MerkleRoot string `json:"merkle_root"`
	Timestamp  int64  `json:"timestamp"`
	Difficulty int    `json:"difficulty"`
	Nonce      int    `json:"nonce"`
}

// MineResult: 채굴 성공 결과
type MineResult struct {
	BlockHash string
	Nonce     int
	Header    PoWHeader
}

// 헤더를 직렬화해 해시 계산
func powComputeHash(header PoWHeader) string {
	data, _ := json.Marshal(header)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// validHash: 난이도 조건 검사
func validHash(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

// mineBlock: PoW 수행 (모든 노드에서 동시에 실행)
func mineBlock(prevHash, merkleRoot string, index, difficulty int) MineResult {
	miningStop.Store(false)

	header := PoWHeader{
		Index:      index,
		PrevHash:   prevHash,
		MerkleRoot: merkleRoot,
		Timestamp:  time.Now().Unix(),
		Difficulty: difficulty,
	}

	nonce := rand.Intn(5000) // 시작점 랜덤
	var hash string

	for !miningStop.Load() {
		header.Nonce = nonce
		hash = powComputeHash(header)
		if validHash(hash, difficulty) {
			log.Printf("[MINER] Success: nonce=%d hash=%s", nonce, hash)
			return MineResult{BlockHash: hash, Nonce: nonce, Header: header}
		}
		nonce++
	}

	// 중단되면 빈 결과 반환
	return MineResult{}
}

// verifyBlock: 브로드캐스트 수신 시 PoW 검증
func verifyBlock(header PoWHeader, expectedPrev string) bool {
	if header.PrevHash != expectedPrev {
		return false
	}
	hash := powComputeHash(header)
	return validHash(hash, header.Difficulty)
}

// broadcastBlock: 성공한 노드가 블록 브로드캐스트
func broadcastBlock(res MineResult, entries any) {
	body, _ := json.Marshal(map[string]any{
		"header":  res.Header,
		"hash":    res.BlockHash,
		"entries": entries,
	})
	for _, peer := range peersSnapshot() {
		go func(addr string) {
			if addr == selfAddr {
				return
			}
			http.Post("http://"+addr+"/block", "application/json", strings.NewReader(string(body)))
		}(peer)
	}
	log.Printf("[BROADCAST] New mined block sent to peers")
}

// handleIncomingBlock: 네트워크 수신 처리 핸들러
func handleIncomingBlock(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		Header  PoWHeader       `json:"header"`
		Hash    string          `json:"hash"`
		Entries []ContentRecord `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer r.Body.Close()

	// 현재 채굴 중이면 즉시 중단
	miningStop.Store(true)

	// 검증
	if !validHash(msg.Hash, msg.Header.Difficulty) {
		log.Printf("[BLOCK] Invalid PoW hash rejected")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 체인에 추가
	addBlockToChain(msg.Header, msg.Hash, msg.Entries)
	log.Printf("[CHAIN] Accepted new block index=%d hash=%s", msg.Header.Index, msg.Hash)
	w.WriteHeader(http.StatusOK)
}

// addBlockToChain: 검증 통과한 블록을 로컬 체인에 추가
func addBlockToChain(header PoWHeader, hash string, entries []ContentRecord) {
	block := LowerBlock{
		Index:      header.Index,
		CpID:       selfID(),
		PrevHash:   header.PrevHash,
		Timestamp:  time.Unix(header.Timestamp, 0).Format(time.RFC3339),
		Entries:    entries,
		MerkleRoot: header.MerkleRoot,
		Nonce:      header.Nonce,
		Difficulty: header.Difficulty,
		BlockHash:  hash,
	}
	saveBlockToDB(block)
	updateIndicesForBlock(block)
	setLatestHeight(block.Index)
}

// selfID: 현재 노드의 CP 식별자 (예시용)
func selfID() string {
	if v, ok := getMeta("meta_cp_id"); ok {
		return v
	}
	return "UNKNOWN_CP"
}
