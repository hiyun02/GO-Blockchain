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
var GlobalDifficulty = 6 // 예: 해시가 "0000"으로 시작해야 성공
// 채굴 상태 플래그
var isMining atomic.Bool

// 채굴 중단 플래그 (다른 노드가 성공하면 true)
var miningStop atomic.Bool

// 채굴 기준시간(1분)
const TargetBlockTime = 60 * time.Second

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

// 네트워크 전체 노드에게 채굴 요청 전달
func triggerNetworkMining(entries []ContentRecord) {
	reqBody, _ := json.Marshal(map[string]any{
		"entries": entries,
	})

	// 노드 주소 목록을 순회하며 채굴 요청 전달
	for _, peer := range peersSnapshot() {
		go func(addr string) {
			http.Post("http://"+addr+"/mine/start", "application/json", strings.NewReader(string(reqBody)))
			log.Printf("[POW][NETWORK] Broadcasted mining start to %s", addr)
		}(peer)
	}
	log.Printf("[PoW][NETWORK] Broadcasted mining start to all peers")
}

// 각 노드에서 채굴 요청 수신 및 채굴 수행
func handleMineStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entries []ContentRecord `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	log.Printf("[PoW][NODE] Received mining start signal")
	// 이미 채굴 중이면 pending에 추가
	if isMining.Load() {
		log.Printf("[POW] already mining => add %d entries to pending", len(req.Entries))
		ch.pendingMu.Lock()
		ch.pending = append(ch.pending, req.Entries...)
		ch.pendingMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
		return
	}
	// 채굴 중이 아니면 즉시 채굴 시작
	go func(entries []ContentRecord) {
		result := mineBlock(GlobalDifficulty, entries)
		if result.BlockHash == "" {
			log.Printf("[POW][NODE] Mining aborted")
			return
		}

		log.Printf("[PoW][NODE] ✅ Mined block #%d hash=%s", result.Header.Index, result.BlockHash[:12])
		broadcastBlock(result, entries)

		// 채굴 끝났으니 pending 처리
		processPending()
	}(req.Entries)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "mining started"})

	// 혹시 pending이 또 들어왔고, 시간이 지났으면 재시도
	if len(ch.pending) > 0 && time.Since(ch.lastBlockTime) >= TargetBlockTime {
		log.Printf("[POW][MINE] Re-Running Pending MINE Process")
		processPending()
	}
}

// PoW 채굴 수행
// 항상 현재 로컬 체인 상태 기반으로 시작
func mineBlock(difficulty int, entries []ContentRecord) MineResult {

	miningStop.Store(false)
	isMining.Store(true)

	// LevelDB 장부에서 마지막 블록 조회
	prevH, ok := getLatestHeight()
	if !ok || prevH < 0 {
		log.Printf("[PoW] ERROR: mineBlock called but genesis should be mined separately.")
		isMining.Store(false)
		return MineResult{}
	}

	prev, err := getBlockByIndex(prevH)
	if err != nil {
		log.Printf("[PoW] Failed to load previous block: %v", err)
		isMining.Store(false)
		return MineResult{}
	}

	// 새로운 블록 헤더 구성
	index := prev.Index + 1
	prevHash := prev.BlockHash

	leaf := make([]string, len(entries))
	for i, r := range entries {
		leaf[i] = hashContentRecord(r)
	}
	merkleRoot := merkleRootHex(leaf)

	header := PoWHeader{
		Index:      index,
		PrevHash:   prevHash,
		MerkleRoot: merkleRoot,
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
		// 채굴 성공 시
		if validHash(hash, difficulty) {
			log.Printf("[PoW] Success index=%d nonce=%d hash=%s", index, nonce, hash)
			// 난이도 조정
			adjustDifficulty()    // 난이도 조정
			isMining.Store(false) // 채굴 종료 처리
			return MineResult{BlockHash: hash, Nonce: nonce, Header: header}
		}
		nonce++
	}
	isMining.Store(false) // 채굴 종료 처리
	return MineResult{}   // 다른 노드가 성공 시 중단
}

// 채굴 성공하여 블록 전파
func broadcastBlock(res MineResult, entries []ContentRecord) {
	body, _ := json.Marshal(map[string]any{
		"header":  res.Header,
		"hash":    res.BlockHash,
		"entries": entries,
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
	isMining.Store(false)

	// PoW 유효성 검증
	if !validHash(msg.Hash, msg.Header.Difficulty) {
		log.Printf("[PoW][BLOCK] Invalid hash rejected: index=%d", msg.Header.Index)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 체인에 추가
	addBlockToChain(msg.Header, msg.Hash, msg.Entries)
	log.Printf("[PoW][CHAIN] Block accepted: index=%d hash=%s", msg.Header.Index, msg.Hash)
	w.WriteHeader(http.StatusOK)

	// 수신한 후 다시 pending 확인
	if len(ch.pending) > 0 && time.Since(ch.lastBlockTime) >= TargetBlockTime {
		log.Printf("[POW][MINE] Re-Running Pending MINE Process")
		processPending()
	}
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

func processPending() {
	// pending 처리할 체인 참조
	ch.pendingMu.Lock()

	// pending 비었으면 바로 종료
	if len(ch.pending) == 0 {
		ch.pendingMu.Unlock()
		return
	}
	ch.pendingMu.Unlock()

	// 블록 간 최소 간격 충족 확인
	if time.Since(ch.lastBlockTime) < TargetBlockTime {
		log.Printf("[POW] Pending exists but waiting: elapsed=%v < TargetBlockTime=%v",
			time.Since(ch.lastBlockTime), TargetBlockTime)
		return
	}

	// pending에 쌓인 것 가져오기
	ch.pendingMu.Lock()
	entries := ch.pending
	ch.pending = []ContentRecord{} // 큐 초기화
	ch.pendingMu.Unlock()

	log.Printf("[POW] Processing pending entries (%d items)", len(entries))

	// pending 전체를 하나의 블록으로 채굴
	res := mineBlock(GlobalDifficulty, entries)
	if res.BlockHash == "" {
		log.Printf("[POW] Pending mining aborted")
		return
	}

	// 결과 블록 전파
	broadcastBlock(res, entries)
}

// 채굴 난이도 조정
// 호출된 순간: now - lastBlockTime 비교
// 입력/출력 값 없음,  LowerChain 내부 difficulty만 갱신
func adjustDifficulty() {
	now := time.Now()
	elapsed := now.Sub(ch.lastBlockTime)

	if elapsed > TargetBlockTime {
		GlobalDifficulty--
		if GlobalDifficulty < 1 {
			GlobalDifficulty = 1
		}
		log.Printf("[DIFF] Block time= %v > Target ==> Difficulty-- => %d",
			elapsed, GlobalDifficulty)
	} else {
		GlobalDifficulty++
		log.Printf("[DIFF] Block time= %v < Target ==> Difficulty++ => %d",
			elapsed, GlobalDifficulty)
	}

	// 마지막 블록 시간 갱신
	ch.lastBlockTime = now
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
