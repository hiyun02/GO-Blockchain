package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"strings"
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

// 채굴 시 해시 계산 대상 최소 정보
type PoWHeader struct {
	Index      int    `json:"index"`
	PrevHash   string `json:"prev_hash"`
	MerkleRoot string `json:"merkle_root"`
	Timestamp  string `json:"timestamp"`
	Difficulty int    `json:"difficulty"`
	Nonce      int    `json:"nonce"`
}

// 채굴 성공 결과
type MineResult struct {
	BlockHash string
	Nonce     int
	Header    PoWHeader
	Elapsed   float32
}

// 채굴되지 않은 pending 을 감시해서 채굴 시작 신호 보내는 watcher
func startMiningWatcher() {
	t := time.NewTicker(time.Duration(MiningWatcherTime) * time.Second)
	log.Printf("[WATCHER] Mining Watcher Started")

	for range t.C {

		// 이미 채굴 중이거나 메모리풀이 비었으면 아무것도 안함
		if isMining.Load() || pendingIsEmpty() {
			continue
		}
		// 메모리풀에 레코드가 있고 채굴 중이 아니면 채굴 시작 signal
		records := getPending()
		log.Printf("[WATCHER] Pending detected => Starting mining (%d anchors)", len(records))
		sendMiningSignal(records)
	}
}

// 모든 노드에 채굴 요청 전파
func sendMiningSignal(entries []ContentRecord) {
	req, _ := json.Marshal(map[string]any{"entries": entries})
	log.Printf("[POW][NETWORK] Starting Network Mining Order")

	// peerSnapshot은 자기자신을 포함하지 않으므로 추가
	nodes := append(peersSnapshot(), self)
	for _, node := range nodes {
		go func(addr string) {
			http.Post("http://"+addr+"/mine/start", "application/json", strings.NewReader(string(req)))
			log.Printf("[POW][NETWORK] Broadcasted Mining signal to %s", addr)
		}(node)
	}
	log.Printf("[PoW][NETWORK] Broadcasted mining signal to all peers")
}

// 각 노드에서 채굴 요청 수신 및 채굴 수행
// POST : /mine/start
func handleMineStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entries []ContentRecord `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	entries := req.Entries
	if len(entries) == 0 {
		log.Printf("[PoW][NODE] No entries to mine. Skip.")
		return
	}
	// CAS: mining 시작 시점 보호
	if !isMining.CompareAndSwap(false, true) {
		log.Printf("[PoW][NODE] Mining already in progress => cancel new mining")
		return
	}

	log.Printf("[PoW][NODE] Received mining start signal with entries: %d", len(entries))
	go func(entries []ContentRecord) {
		// entries를 활용해 실제 채굴 시작
		result := mineBlock(GlobalDifficulty, entries)
		if result.BlockHash == "" {
			log.Printf("[POW][NODE] Mining aborted")
			return
		}
		log.Printf("[PoW][NODE] ✅ Success New Block Mining #%d hash=%s elapsed=%ds", result.Header.Index, result.BlockHash[:12], result.Elapsed)
		adjustDifficulty(result.Header.Index, result.Elapsed) // 채굴 난이도 조정
		broadcastBlock(result, entries)

	}(entries)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "mining started"})

}

// PoW 채굴 수행
// 항상 현재 로컬 체인 상태 기반으로 시작
func mineBlock(difficulty int, entries []ContentRecord) MineResult {

	miningStop.Store(false)
	mineStart := time.Now()
	// LevelDB 장부에서 마지막 블록 인덱스 조회
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
		Timestamp:  time.Unix(time.Now().Unix(), 0).Format(time.RFC3339),
		Difficulty: difficulty,
	}

	log.Printf("[PoW] Starting mining (index=%d prev=%s...)", index, prevHash[:8])

	// Nonce 탐색
	rand.Seed(time.Now().UnixNano())
	nonce := rand.Intn(4294967296)

	var hash string

	for !miningStop.Load() {
		header.Nonce = nonce
		hash = computeHashForPoW(header)
		// 채굴 성공 시
		if validHash(hash, difficulty) {
			mineEnd := time.Now()
			elapsed := mineEnd.Sub(mineStart)
			//isMining.Store(false) // nonce 찾기는 끝났지만, 아직 저장되지 않았으므로 플래그 변경하지 않음
			return MineResult{BlockHash: hash, Nonce: nonce, Header: header, Elapsed: float32(elapsed.Seconds())}
		}
		nonce++
	}
	log.Printf("[PoW] Stop PoW by Winner Node")
	return MineResult{} // 다른 노드가 성공 시 중단
}

// 채굴 성공하여 블록 전파
func broadcastBlock(res MineResult, entries []ContentRecord) {
	body, _ := json.Marshal(map[string]any{
		"header":     res.Header,
		"hash":       res.BlockHash,
		"entries":    entries,
		"difficulty": GlobalDifficulty,
		"elapsed":    res.Elapsed,
		"winner":     self,
	})
	// peerSnapshot은 자기자신을 포함하지 않으므로 추가
	nodes := append(peersSnapshot(), self)
	for _, node := range nodes {
		go func(addr string) {
			http.Post("http://"+addr+"/receiveBlock", "application/json", strings.NewReader(string(body)))
		}(node)
	}
	log.Printf("[PoW][P2P][BROADCAST] Winner sent NewBlock to peers: index=%d hash=%s", res.Header.Index, res.BlockHash)
}

// PoW 수행 중 승자노드로부터 신규 블록 수신하면 검증한 후 체인에 추가함
// POST : /receiveBlock 요청을 통해 트리거
func receiveBlock(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		Header     PoWHeader       `json:"header"`
		Hash       string          `json:"hash"`
		Entries    []ContentRecord `json:"entries"`
		Difficulty int             `json:"difficulty"`
		Elapsed    float32         `json:"elapsed"`
		Winner     string          `json:"winner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer r.Body.Close()

	// 이미 해당 인덱스의 블록이 존재하면 무시
	if _, err := getBlockByIndex(msg.Header.Index); err == nil {
		log.Printf("[PoW][NODE] Block #%d already exists -> ignore duplicate receiveBlock", msg.Header.Index)
		return
	}
	// 들어온 블록이 중복된 블록이 아니라면, pow 즉시 중단
	// 검증 없이 중단하면, 4번블록 채굴 중 3번블록 들어왔을 때 4번블록 채굴이 멈춤
	miningStop.Store(true)
	log.Printf("[PoW][NODE] The Winner Node is : %s", msg.Winner)
	// PoW 유효성 검증 (기존 난이도로 검증)
	if !validHash(msg.Hash, msg.Header.Difficulty) {
		log.Printf("[PoW][BLOCK] Invalid hash rejected: index=%d", msg.Header.Index)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 체인에 추가
	addBlockToChain(msg.Header, msg.Hash, msg.Elapsed, msg.Entries)
	log.Printf("[PoW][CHAIN] Block accepted: index=%d hash=%s", msg.Header.Index, msg.Hash)
	w.WriteHeader(http.StatusOK)

	// 채굴된 블록의 난이도와 전달받은 난이도가 같지 않다면 전달받은 난이도를 전역변수에 반영
	if msg.Difficulty != msg.Header.Difficulty {
		GlobalDifficulty = msg.Difficulty
	}
	isMining.Store(false) // 장부 추가가 끝난 후 isMining 종료처리 => 다음 블록 채굴 가능한 상태가 됨
}

// 검증된 블록을 로컬 체인에 추가
func addBlockToChain(header PoWHeader, hash string, elapsed float32, entries []ContentRecord) {
	block := LowerBlock{
		Index:      header.Index,
		CpID:       selfID(),
		PrevHash:   header.PrevHash,
		Timestamp:  header.Timestamp,
		Entries:    entries,
		MerkleRoot: header.MerkleRoot,
		Nonce:      header.Nonce,
		Difficulty: header.Difficulty,
		BlockHash:  hash,
		Elapsed:    elapsed,
	}
	onBlockReceived(block)
}

// 세 블록 마다 채굴 소요시간에 따른 채굴 난이도 조정
func adjustDifficulty(idx int, elapsed float32) {

	log.Printf("[DIFF] Adjust Difficulty Start! Index = %d", idx)
	// 3 블록의 소요시간 담을 배열 (0으로 초기화)
	e := [3]float32{}
	// 최신블록 채굴소요시간
	e[2] = elapsed
	if idx > 2 {
		// 직전 블록 조회
		b1, err1 := getBlockByIndex(idx - 1)
		if err1 != nil {
			log.Printf("[DIFF] Previous Block fetch error ")
		} else { // 직전블록 채굴소요시간
			e[1] = b1.Elapsed
		}
		// 전전 블록 조회
		b2, err2 := getBlockByIndex(idx - 2)
		if err2 != nil {
			log.Printf("[DIFF] Pre-Previous Block fetch error")
		} else { // 전전블록 채굴소요시간
			e[0] = b2.Elapsed
		}
	}
	avg := (float64)(e[0]+e[1]+e[2]) / 3.0
	ratio := avg / float64(DiffStandardTime)

	log.Printf("[DIFF] 3-block average elapsed = %.2f sec , ratio : %.2f (b0=%d b1=%d b2=%d)",
		avg, ratio, e[0], e[1], e[2])

	// 너무 일찍 끝났다면 난이도 올림
	if ratio < 0.85 {
		GlobalDifficulty++
		log.Printf("[DIFF] Increased difficulty => %d", GlobalDifficulty)
		if GlobalDifficulty == 8 {
			GlobalDifficulty--
		}

	} else if ratio > 1.25 { // 너무 오래 걸렸다면 난이도 낮춤
		GlobalDifficulty--
		if GlobalDifficulty < 1 {
			GlobalDifficulty = 1
		}
		log.Printf("[DIFF] Decreased difficulty => %d", GlobalDifficulty)
	} else {
		log.Printf("[DIFF] No difficulty change (within normal range)")
	}

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
