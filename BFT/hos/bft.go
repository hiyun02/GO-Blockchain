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
	Timestamp  string `json:"timestamp"`
	Difficulty int    `json:"difficulty"`
	Nonce      int    `json:"nonce"`
}

// 채굴 성공 결과
type MineResult struct {
	BlockHash  string
	Nonce      int
	Header     PoWHeader
	Elapsed    float32
	LeafHashes []string
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
func sendMiningSignal(entries []ClinicRecord) {
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
		Entries []ClinicRecord `json:"entries"`
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
	go func(entries []ClinicRecord) {
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

// 채굴 성공하여 블록 전파
func broadcastBlock(res MineResult, entries []ClinicRecord) {
	body, _ := json.Marshal(map[string]any{
		"header":     res.Header,
		"hash":       res.BlockHash,
		"entries":    entries,
		"elapsed":    res.Elapsed,
		"leafHashes": res.LeafHashes,
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
		Header     PoWHeader      `json:"header"`
		Hash       string         `json:"hash"`
		Entries    []ClinicRecord `json:"entries"`
		Difficulty int            `json:"difficulty"`
		Elapsed    float32        `json:"elapsed"`
		LeafHashes []string       `json:"leafHashes"`
		Winner     string         `json:"winner"`
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

	// 체인에 추가
	addBlockToChain(msg.Header, msg.Hash, msg.Elapsed, msg.Entries, msg.LeafHashes)
	log.Printf("[PoW][CHAIN] Block accepted: index=%d hash=%s", msg.Header.Index, msg.Hash)
	w.WriteHeader(http.StatusOK)

	isMining.Store(false) // 장부 추가가 끝난 후 isMining 종료처리 => 다음 블록 채굴 가능한 상태가 됨
}

// 검증된 블록을 로컬 체인에 추가
func addBlockToChain(header PoWHeader, hash string, elapsed float32, entries []ClinicRecord, leafHashes []string) {
	block := LowerBlock{
		Index:      header.Index,
		HosID:      selfID(),
		PrevHash:   header.PrevHash,
		Timestamp:  header.Timestamp,
		Entries:    entries,
		MerkleRoot: header.MerkleRoot,
		BlockHash:  hash,
		Elapsed:    elapsed,
		LeafHashes: leafHashes,
	}
	onBlockReceived(block)
}

// 헤더 직렬화 후 SHA-256 해시 계산
func computeHashForPoW(header PoWHeader) string {
	data, _ := json.Marshal(header)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
