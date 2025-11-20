package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
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
	Timestamp  int64  `json:"timestamp"`
	Difficulty int    `json:"difficulty"`
	Nonce      int    `json:"nonce"`
}

// 채굴 성공 결과
type MineResult struct {
	BlockHash string
	Nonce     int
	Header    PoWHeader
	Elapsed   int64
}

// 네트워크 전체에 채굴 요청 혹은 Entries를 전달
func triggerNetworkMining(entries []ContentRecord) {
	req, _ := json.Marshal(map[string]any{"entries": entries})
	// 넘겨받은 entries가 비어있지 않다면
	if len(entries) != 0 {
		appendPending(entries)
		// 이미 채굴 중이면 네트워크에 entries 전파
		if isMining.Load() {
			log.Printf("[POW] Already Mining => add %d entries to Network's Pending", len(entries))
			// 노드 주소 목록을 순회하며 신규 entries 전달
			for _, peer := range peersSnapshot() {
				go func(addr string) {
					http.Post("http://"+addr+"/receivePending", "application/json", strings.NewReader(string(req)))
					log.Printf("[POW][NETWORK] Broadcasted Pending to %s", addr)
				}(peer)
			}
		}
	} else {
		log.Printf("[WARRN] There are No entries, Checking Next Mine Signal")
	}
	// 채굴여부에 따라 채굴 신호 전파 (채굴종료 직후 남아있는 pending 기반 채굴 요청도 처리 가능)
	if !isMining.Load() {
		log.Printf("[POW][NETWORK] Starting Network Mining Order")
		isMining.Store(true) // 즉시 채굴 중으로 변경
		for _, peer := range peersSnapshot() {
			go func(addr string) {
				http.Post("http://"+addr+"/mine/start", "application/json", strings.NewReader(string(req)))
				log.Printf("[POW][NETWORK] Broadcasted Mining signal to %s", addr)
			}(peer)
		}
		http.Post("http://"+self+"/mine/start", "application/json", strings.NewReader(string(req)))
		log.Printf("[PoW][NETWORK] Broadcasted mining signal to all peers")
	}
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

	log.Printf("[PoW][NODE] Received mining start signal with entries: %d", len(req.Entries))
	appendPending(req.Entries)
	entries := popPending() // pending에 쌓여있던 entries를 불러옴
	log.Printf("[PoW][NODE] Received mining start signal with Pending entries: %d", len(entries))
	go func(entries []ContentRecord) {
		// 꺼낸 entries를 활용해 실제 채굴 시작
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
	isMining.Store(true)
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
			mineEnd := time.Now()
			elapsed := mineEnd.Sub(mineStart)
			isMining.Store(false) // 채굴 종료 처리
			return MineResult{BlockHash: hash, Nonce: nonce, Header: header, Elapsed: int64(elapsed.Seconds())}
		}
		nonce++
	}
	isMining.Store(false) // 채굴 종료 처리
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
	for _, peer := range peersSnapshot() {
		go func(addr string) {
			http.Post("http://"+addr+"/receiveBlock", "application/json", strings.NewReader(string(body)))
		}(peer)
	}
	http.Post("http://"+self+"/receiveBlock", "application/json", strings.NewReader(string(body)))
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
		Elapsed    int64           `json:"elapsed"`
		Winner     string          `json:"winner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer r.Body.Close()

	// 현재 채굴 즉시 중단
	miningStop.Store(true)
	isMining.Store(false)
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

	// 승자노드는, 다음 채굴이 가능하다면 트리거될 수 있도록 검사
	if msg.Winner == self && !pendingIsEmpty() {
		log.Printf("[POW][CHAIN] Winner Node Trigger Next Mining")
		go triggerNextMining()
	}
}

// 검증된 블록을 로컬 체인에 추가
func addBlockToChain(header PoWHeader, hash string, elapsed int64, entries []ContentRecord) {
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
		Elapsed:    elapsed,
	}
	onBlockReceived(block)
}

// 세 블록 마다 채굴 소요시간에 따른 채굴 난이도 조정
func adjustDifficulty(idx int, elapsed int64) {

	if idx%3 == 0 {
		log.Printf("[DIFF] Adjust Difficulty Start! Index = %d", idx)
		// 3 블록의 소요시간 담을 배열 (0으로 초기화)
		e := [3]int64{}
		// 최신블록 채굴소요시간
		e[2] = elapsed
		if idx > 2 {
			// 직전 블록 조회
			b1, err1 := getBlockByIndex(idx - 1)
			if err1 != nil {
				log.Printf("[DIFF] Previous Block fetch error ")
			} else {
				e[1] = b1.Elapsed
			} // 직전블록 채굴소요시간
			// 그 전 블록 조회
			b2, err2 := getBlockByIndex(idx - 2)
			if err2 != nil {
				log.Printf("[DIFF] PRe-Previous Block fetch error")
			} else {
				e[0] = b2.Elapsed
			} // 직전블록의 전블록 채굴소요시간
		}

		avg := (float64)(e[0]+e[1]+e[2]) / 3.0
		ratio := avg / float64(TargetBlockTime)

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

	} else {
		log.Printf("[DIFF] Don't Adjust Difficulty! Index = %d", idx)
	}
}
func triggerNextMining() {
	time.Sleep(10 * time.Millisecond) // receiveBlock에게 처리할 시간
	if !isMining.Load() {
		triggerNetworkMining([]ContentRecord{})
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
