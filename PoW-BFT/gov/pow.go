package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const sha256HexLength = sha256.Size * 2

var powHTTPClient = &http.Client{Timeout: 3 * time.Second}

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
	Index             int    `json:"index"`
	PrevHash          string `json:"prev_hash"`
	MerkleRoot        string `json:"merkle_root"`
	ConfigurationHash string `json:"configuration_hash,omitempty"`
	Timestamp         string `json:"timestamp"`
	Difficulty        int    `json:"difficulty"`
	Nonce             uint64 `json:"nonce"`
}

// 채굴 성공 결과
type MineResult struct {
	BlockHash string
	Nonce     uint64
	Header    PoWHeader
	Elapsed   float32
}

// 채굴되지 않은 pending 을 감시해서 채굴 시작 신호 보내는 watcher
func startMiningWatcher() {
	t := time.NewTicker(time.Duration(MiningWatcherTime) * time.Second)
	log.Printf("[WATCHER] Mining Watcher Started")

	for range t.C {

		// 이미 채굴 중이거나 메모리풀이 비었으면 아무것도 안함
		if isMining.Load() || getPendingCnt() == 0 {
			continue
		}

		// 메모리풀에 레코드가 있고 채굴 중이 아니면 채굴 시작 signal
		records := popPending()
		log.Printf("[WATCHER] Pending detected => Starting mining (%d anchors)", len(records))
		sendMiningSignal(records)
	}
}

// 모든 노드에 채굴 요청 전파
func sendMiningSignal(anchors []AnchorRecord) {
	participants := miningParticipants()
	req, _ := json.Marshal(PoWMiningRequest{
		Anchors: anchors, Participants: participants, Difficulty: GlobalDifficulty,
	})
	log.Printf("[POW][NETWORK] Starting Network Mining Order")

	for _, node := range participants {
		go func(addr string) {
			response, err := powHTTPClient.Post("http://"+addr+"/mine/start", "application/json", strings.NewReader(string(req)))
			if err != nil {
				log.Printf("[POW][NETWORK] %s 채굴 시작 신호 전송 실패: %v", addr, err)
				return
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, response.Body)
			log.Printf("[POW][NETWORK] Broadcasted Mining signal to %s", addr)
		}(node)
	}
	log.Printf("[PoW][NETWORK] Broadcasted mining signal to all peers")
}

// 각 노드에서 채굴 요청 수신 및 채굴 수행
// GET /mine/start
func handleMineStart(w http.ResponseWriter, r *http.Request) {
	var req PoWMiningRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	anchors := req.Anchors
	if len(anchors) == 0 {
		log.Printf("[PoW][NODE] No anchors to mine. Skip.")
		return
	}
	// CAS: mining 시작 시점 보호
	if !isMining.CompareAndSwap(false, true) {
		log.Printf("[PoW][NODE] Mining already in progress => cancel new mining")
		return
	}
	if req.Difficulty > 0 {
		GlobalDifficulty = req.Difficulty
	}
	participants := req.Participants
	if len(participants) == 0 {
		participants = miningParticipants()
	}

	log.Printf("[PoW][NODE] Received mining start signal with anchors: %d", len(anchors))
	go func(anchors []AnchorRecord, participants []string) {
		// entries를 활용해 실제 채굴 시작
		result := mineBlock(GlobalDifficulty, anchors)
		if result.BlockHash == "" {
			log.Printf("[POW][NODE] Mining aborted")
			return
		}
		log.Printf("[PoW][NODE] ✅ Success New Block Mining #%d hash=%s elapsed=%.4fs", result.Header.Index, result.BlockHash[:12], result.Elapsed)
		adjustDifficulty(result.Header.Index, result.Elapsed) // 채굴 난이도 조정
		broadcastBlock(result, anchors, participants)

	}(anchors, participants)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "mining started"})
}

// PoW 채굴 수행
// 항상 현재 로컬 체인 상태 기반으로 시작
func mineBlock(difficulty int, anchors []AnchorRecord) MineResult {

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

	// AnchorRecord 기반 MerkleRoot 계산
	mergedRoot := computeUpperMerkleRoot(anchors)

	header := PoWHeader{
		Index:             index,
		PrevHash:          prevHash,
		MerkleRoot:        mergedRoot,
		ConfigurationHash: computePoWRepresentativeChangesHash(anchors),
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
		Difficulty:        difficulty,
	}

	log.Printf("[PoW] Starting mining (index=%d prev=%s...)", index, prevHash[:8])

	// uint64 전체 범위(0 ~ 2^64-1)에서 임의의 시작 Nonce를 선택해 탐색한다.
	// uint64이므로 음수 Nonce는 생성되지 않는다.
	startNonce := randomUint64()
	nonce := startNonce

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
		if nonce == ^uint64(0) {
			nonce = 0
		} else {
			nonce++
		}
		if nonce == startNonce {
			// 같은 헤더의 uint64 범위를 모두 검사한 경우 timestamp를 바꿔 새 탐색 공간을 만든다.
			header.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
			startNonce = randomUint64()
			nonce = startNonce
			log.Printf("[PoW] 전체 Nonce 범위를 순회하여 timestamp를 갱신하고 다시 탐색합니다.")
		}
	}
	log.Printf("[PoW] Stop PoW by Winner Node")
	return MineResult{} // 다른 노드가 성공 시 중단
}

// 채굴 성공 시 네트워크로 블록 전파
func broadcastBlock(res MineResult, anchors []AnchorRecord, participants []string) {
	body, _ := json.Marshal(map[string]any{
		"header":     res.Header,
		"hash":       res.BlockHash,
		"entries":    anchors,
		"difficulty": GlobalDifficulty,
		"elapsed":    res.Elapsed,
		"winner":     self,
	})
	if len(participants) == 0 {
		participants = miningParticipants()
	}
	for _, node := range participants {
		go func(addr string) {
			response, err := powHTTPClient.Post("http://"+addr+"/receiveBlock", "application/json", strings.NewReader(string(body)))
			if err != nil {
				log.Printf("[PoW][P2P] %s 블록 전파 실패: %v", addr, err)
				return
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, response.Body)
		}(node)
	}
	log.Printf("[PoW][P2P][BROADCAST] Winner sent NewBlock to peers: index=%d hash=%s", res.Header.Index, res.BlockHash)
}

// PoW 수행 중 승자노드로부터 신규 블록 수신하면 검증한 후 체인에 추가함
// POST : /receive 요청을 통해 트리거
func receiveBlock(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		Header     PoWHeader      `json:"header"`
		Hash       string         `json:"hash"`
		Anchors    []AnchorRecord `json:"entries"`
		Difficulty int            `json:"difficulty"`
		Elapsed    float32        `json:"elapsed"`
		Winner     string         `json:"winner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	log.Printf("[PoW][NODE] The Winner Node is : %s", msg.Winner)
	// 헤더 해시, 난이도, 머클루트, 높이와 이전 해시를 모두 검증한 뒤 체인에 추가한다.
	if err := addBlockToChain(msg.Header, msg.Hash, msg.Elapsed, msg.Anchors); err != nil {
		log.Printf("[PoW][BLOCK] Invalid block rejected: index=%d err=%v", msg.Header.Index, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("[PoW][CHAIN] Block accepted: index=%d hash=%s", msg.Header.Index, msg.Hash)
	w.WriteHeader(http.StatusOK)

	// 승자가 계산한 다음 난이도로 덮어써 패배 노드의 임시 난이도 변경도 되돌린다.
	if msg.Difficulty >= 1 && msg.Difficulty <= sha256HexLength {
		GlobalDifficulty = msg.Difficulty
	}
	isMining.Store(false) // 장부 추가가 끝난 후 isMining 종료처리 => 다음 블록 채굴 가능한 상태가 됨
}

// 검증된 블록을 로컬 체인에 추가
func addBlockToChain(header PoWHeader, hash string, elapsed float32, anchors []AnchorRecord) error {
	block := UpperBlock{
		Index:             header.Index,
		GovID:             selfID(),
		PrevHash:          header.PrevHash,
		Timestamp:         header.Timestamp,
		Records:           anchors,
		MerkleRoot:        header.MerkleRoot,
		ConfigurationHash: header.ConfigurationHash,
		Nonce:             header.Nonce,
		Difficulty:        header.Difficulty,
		BlockHash:         hash,
		Elapsed:           elapsed,
	}
	return onBlockReceived(block)
}

func randomUint64() uint64 {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(fmt.Sprintf("안전한 PoW Nonce 생성 실패: %v", err))
	}
	return binary.BigEndian.Uint64(value[:])
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

	log.Printf("[DIFF] 3-block average elapsed = %.2f sec , ratio : %.2f (b0=%.2f b1=%.2f b2=%.2f)",
		avg, ratio, e[0], e[1], e[2])

	// 너무 일찍 끝났다면 난이도 올림
	if ratio < 0.85 {
		GlobalDifficulty++
		log.Printf("[DIFF] Increased difficulty => %d", GlobalDifficulty)
		if GlobalDifficulty == 8 {
			GlobalDifficulty--
			log.Printf("[DIFF] Decreased difficulty 8 => %d", GlobalDifficulty)
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
	if len(hash) != sha256HexLength || difficulty < 1 || difficulty > sha256HexLength {
		return false
	}
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}
