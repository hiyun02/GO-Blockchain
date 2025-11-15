package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// PoW (Proof of Work) 모듈
// ------------------------------------------------------------
// - 모든 노드가 동시에 채굴 수행
// - 난이도 조건을 가장 먼저 만족한 노드가 블록 브로드캐스트
// - 다른 노드는 즉시 채굴 중단 후 검증(verifyBlock) → 체인에 추가
// - 동일한 GlobalDifficulty 사용
////////////////////////////////////////////////////////////////////////////////

// 전역 난이도 설정 (모든 노드 동일)
const GlobalDifficulty = 4 // 예: 해시가 "0000"으로 시작해야 성공

// 채굴 중단 플래그 (다른 노드가 성공하면 true)
var miningStop atomic.Bool

// 채굴 시 해시 계산 대상 최소 정보
type PoWHeader struct {
	Index      int    `json:"index"`
	PrevHash   string `json:"prev_hash"`
	MerkleRoot string `json:"merkle_root"`
	Timestamp  int64  `json:"timestamp"`
	Difficulty int    `json:"difficulty"`
	Nonce      int    `json:"nonce"`
}

// 채굴 성공 결과
type MineResult struct {
	BlockHash string
	Nonce     int
	Header    PoWHeader
}

// 헤더 직렬화 후 SHA-256 해시 계산
func computeHashForPoW(header PoWHeader) string {
	data, _ := json.Marshal(header)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// 주어진 난이도 조건 검사
func validHash(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

// 네트워크 전체 노드에게 채굴 요청 전달
// OTT 체인에서는 AnchorRecord 목록을 기반으로 채굴 수행
func triggerNetworkMining(anchors []AnchorRecord) {
	reqBody, _ := json.Marshal(map[string]any{
		"anchors": anchors,
	})

	// 노드 주소 목록을 순회하며 채굴 요청 전달
	for _, peer := range peersSnapshot() {
		go func(addr string) {
			http.Post("http://"+addr+"/mine/start", "application/json", strings.NewReader(string(reqBody)))
			log.Printf("[POW][NETWORK] Broadcasted mining start to %s", addr)
		}(peer)
	}
	http.Post("http://"+self+"/mine/start", "application/json", strings.NewReader(string(reqBody)))
	log.Printf("[POW][NETWORK] Broadcasted mining start with %d entries", len(anchors))
}

// 각 노드에서 채굴 요청 수신 및 채굴 수행
// GET /mine/start
func handleMineStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Anchors []AnchorRecord `json:"anchors"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	log.Printf("[PoW][NODE] Received mining start signal")

	go func() {
		result := mineBlock(GlobalDifficulty, req.Anchors)
		if result.BlockHash == "" {
			log.Printf("[POW][NODE] Mining aborted")
			return
		}
		log.Printf("[POW][NODE] ✅ Mined block hash=%s", result.BlockHash[:12])
		broadcastBlock(result, req.Anchors)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "mining started"})
}

// PoW 채굴 수행
// 항상 현재 로컬 체인 상태 기반으로 시작
func mineBlock(difficulty int, anchors []AnchorRecord) MineResult {
	miningStop.Store(false)

	// LevelDB 장부에서 현재 마지막 블록 조회
	prevH, ok := getLatestHeight()
	if !ok {
		log.Printf("[PoW] No previous block found (genesis only)")
		return MineResult{}
	}
	prev, err := getBlockByIndex(prevH)
	if err != nil {
		log.Printf("[PoW] Failed to load previous block: %v", err)
		return MineResult{}
	}

	// 새로운 블록 헤더 구성
	index := prev.Index + 1
	prevHash := prev.BlockHash

	// AnchorRecord 기반 MerkleRoot 계산
	mergedRoot := computeUpperMerkleRoot(anchors)

	header := PoWHeader{
		Index:      index,
		PrevHash:   prevHash,
		MerkleRoot: mergedRoot,
		Timestamp:  time.Now().Unix(),
		Difficulty: difficulty,
	}

	log.Printf("[PoW] Starting mining (index=%d prev=%s...)", index, prevHash[:8])

	// Nonce 탐색
	nonce := 0
	var hash string

	for !miningStop.Load() {
		header.Nonce = nonce
		hash = computeHashForPoW(header)
		if validHash(hash, difficulty) {
			log.Printf("[PoW] Success index=%d nonce=%d hash=%s", index, nonce, hash)
			return MineResult{BlockHash: hash, Nonce: nonce, Header: header}
		}
		nonce++
	}
	return MineResult{} // 다른 노드가 성공 시 중단
}

// 채굴 성공 시 네트워크로 블록 전파
func broadcastBlock(res MineResult, anchors []AnchorRecord) {
	body, _ := json.Marshal(map[string]any{
		"header":  res.Header,
		"hash":    res.BlockHash,
		"entries": anchors,
	})
	for _, peer := range peersSnapshot() {
		go func(addr string) {
			http.Post("http://"+addr+"/receive", "application/json", strings.NewReader(string(body)))
		}(peer)
	}
	http.Post("http://"+self+"/receive", "application/json", strings.NewReader(string(body)))
	log.Printf("[PoW][P2P][BROADCAST] Winner sent NewBlock to peers: index=%d hash=%s", res.Header.Index, res.BlockHash)
}

// PoW 수행 중 승자노드로부터 신규 블록 수신하면 검증한 후 체인에 추가함
// POST : /receive 요청을 통해 트리거
func receive(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		Header  PoWHeader      `json:"header"`
		Hash    string         `json:"hash"`
		Anchors []AnchorRecord `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer r.Body.Close()

	// 현재 채굴 즉시 중단
	miningStop.Store(true)

	// PoW 유효성 검증
	if !validHash(msg.Hash, msg.Header.Difficulty) {
		log.Printf("[PoW][BLOCK] Invalid hash rejected: index=%d", msg.Header.Index)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 체인에 추가
	addBlockToChain(msg.Header, msg.Hash, msg.Anchors)
	log.Printf("[PoW][CHAIN] Block accepted: index=%d hash=%s", msg.Header.Index, msg.Hash)
	w.WriteHeader(http.StatusOK)
}

// 검증된 블록을 로컬 체인에 추가
func addBlockToChain(header PoWHeader, hash string, anchors []AnchorRecord) {
	block := UpperBlock{
		Index:      header.Index,
		OttID:      selfID(),
		PrevHash:   header.PrevHash,
		Timestamp:  time.Unix(header.Timestamp, 0).Format(time.RFC3339),
		Records:    anchors,
		MerkleRoot: header.MerkleRoot,
		Nonce:      header.Nonce,
		Difficulty: header.Difficulty,
		BlockHash:  hash,
	}
	onBlockReceived(block)
}
