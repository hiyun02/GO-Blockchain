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
// 네트워크 전체 노드에게 채굴 요청 전달 (부트노드가 최초로 실행)
func triggerNetworkMining() {
	// 현재 마지막 블록을 LevelDB에서 조회
	prevH, ok := getLatestHeight()
	if !ok {
		log.Printf("[POW] No previous block found (genesis only)")
		return
	}
	prev, err := getBlockByIndex(prevH)
	if err != nil {
		log.Printf("[POW] Failed to load previous block: %v", err)
		return
	}

	// 채굴 대상 블록 정보 구성
	index := prev.Index + 1
	prevHash := prev.BlockHash

	// 아직 블록 안에 담을 트랜잭션(Entries)이 없다면 빈 리스트로
	entries := []ContentRecord{}
	leaf := make([]string, len(entries))
	for i, r := range entries {
		leaf[i] = hashContentRecord(r)
	}
	merkleRoot := merkleRootHex(leaf)

	reqBody, _ := json.Marshal(map[string]any{
		"prev_hash":   prevHash,
		"merkle_root": merkleRoot,
		"index":       index,
	})

	log.Printf("[POW] Starting mining for block #%d (prev=%s...)", index, prevHash[:8])

	// 네트워크 내 모든 노드에게 채굴 요청 전달
	for _, peer := range peersSnapshot() {
		go func(addr string) {
			if addr == self {
				return // 자기 자신에게는 전달할 필요 없음
			}
			http.Post("http://"+addr+"/mine/start", "application/json", strings.NewReader(string(reqBody)))
		}(peer)
	}

	// 자기 자신도 채굴 시작
	go func() {
		result := mineBlock(prevHash, merkleRoot, index, GlobalDifficulty)
		if result.BlockHash == "" {
			log.Printf("[POW] This Node mining aborted (index=%d)", index)
			return
		}
		log.Printf("[POW] This Node mined block #%d hash=%s", index, result.BlockHash[:12])
		broadcastBlock(result, entries)
	}()
}

// 네트워크 내 각 노드가 채굴을 요청받아 시작
// GET /mine/start
func handleMineStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrevHash   string `json:"prev_hash"`
		MerkleRoot string `json:"merkle_root"`
		Index      int    `json:"index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	log.Printf("[MINER] Received mining start command (index=%d)", req.Index)

	go func() {
		result := mineBlock(req.PrevHash, req.MerkleRoot, req.Index, GlobalDifficulty)
		if result.BlockHash == "" {
			log.Printf("[MINER] Mining aborted (index=%d)", req.Index)
			return
		}
		log.Printf("[MINER] Mined block: %s", result.BlockHash)
		broadcastBlock(result, nil)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "mining started",
	})
}

// PoW 블록 채굴 수행
func mineBlock(prevHash, merkleRoot string, index, difficulty int) MineResult {
	miningStop.Store(false) // 초기화

	header := PoWHeader{
		Index:      index,
		PrevHash:   prevHash,
		MerkleRoot: merkleRoot,
		Timestamp:  time.Now().Unix(),
		Difficulty: difficulty,
	}

	nonce := rand.Intn(10000) // 무작위 시작점
	var hash string

	for !miningStop.Load() {
		header.Nonce = nonce
		hash = computeHashForPoW(header)

		if validHash(hash, difficulty) {
			log.Printf("[MINER] Success: index=%d nonce=%d hash=%s", index, nonce, hash)
			return MineResult{BlockHash: hash, Nonce: nonce, Header: header}
		}
		nonce++
	}

	return MineResult{} // 다른 노드 성공 시 중단
}

// 채굴 성공 시 네트워크로 블록 전파
func broadcastBlock(res MineResult, entries any) {
	body, _ := json.Marshal(map[string]any{
		"header":  res.Header,
		"hash":    res.BlockHash,
		"entries": entries,
	})
	for _, peer := range peersSnapshot() {
		go func(addr string) {
			if addr == self {
				return
			}
			http.Post("http://"+addr+"/receive", "application/json", strings.NewReader(string(body)))
		}(peer)
	}
	log.Printf("[P2P][POW][BROADCAST] Winner sent NewBlock to peers: index=%d hash=%s", res.Header.Index, res.BlockHash)
}

// PoW 수행 중 승자노드로부터 신규 블록 수신하면 검증한 후 체인에 추가함
// POST : /receive 요청을 통해 트리거
func receive(w http.ResponseWriter, r *http.Request) {
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

	// 현재 채굴 즉시 중단
	miningStop.Store(true)

	// PoW 유효성 검증
	if !validHash(msg.Hash, msg.Header.Difficulty) {
		log.Printf("[BLOCK] Invalid hash rejected: index=%d", msg.Header.Index)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 체인에 추가
	addBlockToChain(msg.Header, msg.Hash, msg.Entries)
	log.Printf("[CHAIN] Block accepted: index=%d hash=%s", msg.Header.Index, msg.Hash)
	w.WriteHeader(http.StatusOK)
}

// 검증된 블록을 로컬 체인에 추가
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
	onBlockReceived(block)
}
