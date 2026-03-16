package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	consensusInProgress atomic.Bool
	ConsensusBatchSize  = 200
)

const (
	PhaseIdle int32 = iota
	PhasePrePrepare
	PhasePrepare
	PhaseCommit
	PhaseFinal
	ConsensusTimeout      = 10
	ConsensusBatchSizeMin = 200
	ConsensusBatchSizeMax = 1600
)

type voteCollector struct {
	mu    sync.Mutex
	votes map[string]string
}

func newCollector() *voteCollector {
	return &voteCollector{votes: make(map[string]string)}
}

func (c *voteCollector) add(addr, sig string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.votes[addr]; exists {
		return false
	}
	c.votes[addr] = sig
	return true
}

func (c *voteCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.votes)
}

func (c *voteCollector) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	sigs := make([]string, 0, len(c.votes))
	for _, s := range c.votes {
		sigs = append(sigs, s)
	}
	return sigs
}

type viewState struct {
	mu        sync.Mutex
	Phase     int32
	Block     LowerBlock
	Prepare   *voteCollector
	Commit    *voteCollector
	Finalized bool
}

var (
	viewStates = make(map[int]*viewState)
	viewMu     sync.Mutex
)

func getOrCreateView(view int) *viewState {
	viewMu.Lock()
	defer viewMu.Unlock()
	vs, ok := viewStates[view]
	if !ok {
		vs = &viewState{Phase: PhaseIdle, Prepare: newCollector(), Commit: newCollector()}
		viewStates[view] = vs
	}
	return vs
}

func deleteView(view int) {
	viewMu.Lock()
	defer viewMu.Unlock()
	delete(viewStates, view)
}

func quorumSize() int {
	n := len(peersSnapshot()) + 1
	f := (n - 1) / 3
	return 2*f + 1
}

func startConsensusWatcher() {
	ticker := time.NewTicker(time.Second)
	var lastConsensusTime time.Time // 초기화를 하지 않음

	for range ticker.C {
		if self != boot || consensusInProgress.Load() {
			continue
		}

		pendingCnt := getPendingCnt()
		if pendingCnt == 0 {
			lastConsensusTime = time.Time{} // 데이터 없으면 시간 리셋
			ConsensusBatchSize = ConsensusBatchSizeMin
			log.Printf("데이터가 앖으므로 배치 크기 초기화: %d", ConsensusBatchSize)
			continue
		}

		// 첫 데이터가 들어왔을 때 기준 시간 설정
		if lastConsensusTime.IsZero() {
			lastConsensusTime = time.Now()
		}

		// 메모리풀의 엔트리 수가 임계값 이상이거나, 마지막 합의 시점부터 임계대기시간 이후로 지났을 때 합의 수행
		timeSinceLastConsensus := time.Since(lastConsensusTime)

		MaxBatchYN := pendingCnt >= ConsensusBatchSize
		TimeoutYN := timeSinceLastConsensus >= ConsensusTimeout*time.Second
		shouldStart := MaxBatchYN || TimeoutYN
		if !shouldStart {
			// 아직 조건 미달이므로 대기
			continue
		}
		records := popPending()
		// 그사이 비워졌을 경우를 대비한 방어 로직
		if len(records) == 0 {
			continue
		}

		reason := "Timeout"
		// 합의 이유(Reason)에 따른 기준값 변경
		if MaxBatchYN {
			log.Printf("기준값보다 트랜잭션이 많으므로 합의 시작")
			reason = "Full-Batch"
			if ConsensusBatchSize < ConsensusBatchSizeMax {
				log.Printf("현재 배치크기가 상한값보다는 작으므로 트랜잭션이 많으므로 2배 증가")
				ConsensusBatchSize *= 2
				log.Printf("늘어난 배치크기 : %d", ConsensusBatchSize)
			} else {
				log.Printf("배치 크기가 최댓값과 같으므로 늘리지 않음: %d", ConsensusBatchSize)
			}
		} else if TimeoutYN {
			log.Printf("타임아웃이 발생했으므로 합의 시작")
			if ConsensusBatchSize > ConsensusBatchSizeMin {
				log.Printf("배치 크기가 하한값보다는 크므로 절반으로 줄임")
				ConsensusBatchSize /= 2
				log.Printf("감소한 배치 크기 : %d", ConsensusBatchSize)
			} else {
				log.Printf("배치 크기가 하한값과 같으므로 줄이지 않음")
			}
		}

		// PBFT 합의 프로세스 진입
		height, _ := getLatestHeight()
		view := height + 1

		vs := getOrCreateView(view)
		vs.mu.Lock()
		if vs.Phase != PhaseIdle {
			vs.mu.Unlock()
			continue
		}

		// 제안 블록 생성 및 상태 전이
		block := createProposedBlock(records)
		vs.Block = block
		vs.Phase = PhasePrePrepare
		vs.mu.Unlock()

		// 합의 진행 상태 원자적 갱신
		consensusInProgress.Store(true)

		log.Printf("[PBFT][START] View=%d, Entries=%d (Reason: %s, Elapsed: %.1fs)",
			view,
			len(records),
			reason,
			timeSinceLastConsensus.Seconds(),
		)

		// 합의 시작 신호 브로드캐스트
		broadcast("/bft/start", map[string]any{"view": view, "block": block})

		// 마지막 합의 시간 갱신 (반드시 루프 마지막이나 시작 시점에 갱신 확인)
		lastConsensusTime = time.Now()
	}
}

func handleBftStart(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		View  int        `json:"view"`
		Block LowerBlock `json:"block"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		return
	}

	vs := getOrCreateView(msg.View)
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.Phase != PhaseIdle {
		return
	}

	// 블록 검증 로직 (필요시 추가)
	vs.Block = msg.Block
	vs.Phase = PhasePrepare

	myPriv, _ := getMeta("meta_hos_privkey")
	sig := makeAnchorSignature(myPriv, vs.Block.BlockHash, "")
	vs.Prepare.add(self, sig)

	log.Printf("[PBFT][PREPARE] Send Prepare for View %d", msg.View)
	broadcast("/bft/prepare", map[string]any{
		"view": msg.View,
		"addr": self,
		"sig":  sig,
		"hash": vs.Block.BlockHash,
	})
}

func handleReceivePrepare(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		View int
		Addr string
		Sig  string
		Hash string
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		return
	}

	vs := getOrCreateView(msg.View)
	vs.mu.Lock()

	// 블록 정보가 아직 도착 안 했으면 최대 3번(30ms)까지 재시도
	if vs.Block.BlockHash == "" {
		log.Printf("[PBFT][PREPARE] Receive Prepare for View %d", msg.View)
		for i := 0; i < 3; i++ {
			vs.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			vs.mu.Lock()
			if vs.Block.BlockHash != "" {
				break
			}
		}
	}
	defer vs.mu.Unlock()

	// 리더로부터 BftStart(Pre-Prepare)를 아예 못 받은 경우
	if vs.Block.BlockHash == "" {
		return
	}

	// 해시 미스매치 검사
	if vs.Block.BlockHash != msg.Hash {
		log.Printf("[DEBUG] Hash mismatch in Prepare: Expected %s, Got %s", vs.Block.BlockHash, msg.Hash)
		return
	}

	var pub string
	var ok bool
	if msg.Addr == self {
		pub, ok = getMeta("meta_hos_pubkey")
	} else {
		pub, ok = peerPubKeys[msg.Addr]
	}

	if !ok {
		return
	}
	hashBytes, _ := hex.DecodeString(msg.Hash)
	if !verifyECDSA(pub, hashBytes, msg.Sig) {
		return
	}

	if !vs.Prepare.add(msg.Addr, msg.Sig) {
		return
	}

	// 정족수 확인 후 Commit 단계 진입
	if vs.Prepare.count() >= quorumSize() && vs.Phase == PhasePrepare {
		vs.Phase = PhaseCommit
		myPriv, _ := getMeta("meta_hos_privkey")

		sig := makeAnchorSignature(myPriv, vs.Block.BlockHash, "")
		vs.Commit.add(self, sig)

		log.Printf("[PBFT][COMMIT] Quorum reached! Broadcast Commit for View %d", msg.View)
		broadcast("/bft/commit", map[string]any{
			"view": msg.View,
			"addr": self,
			"sig":  sig,
			"hash": vs.Block.BlockHash,
		})
	}
}

func handleReceiveCommit(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		View int
		Addr string
		Sig  string
		Hash string
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		return
	}

	vs := getOrCreateView(msg.View)
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.Block.BlockHash != msg.Hash {
		return
	}

	var pub string
	var ok bool
	if msg.Addr == self {
		pub, ok = getMeta("meta_hos_pubkey")
	} else {
		pub, ok = peerPubKeys[msg.Addr]
	}

	if !ok {
		return
	}
	hashBytes, _ := hex.DecodeString(msg.Hash)
	if !verifyECDSA(pub, hashBytes, msg.Sig) {
		return
	}

	if !vs.Commit.add(msg.Addr, msg.Sig) {
		return
	}

	// 최종 확정 및 저장
	if vs.Commit.count() >= quorumSize() && !vs.Finalized {
		vs.Finalized = true
		vs.Phase = PhaseFinal
		vs.Block.Signatures = vs.Commit.all()

		log.Printf("[PBFT][FINALIZED] View %d Finalized. Saving to DB...", msg.View)

		// [중요] 체인 저장 함수 호출
		onBlockReceived(vs.Block)

		deleteView(msg.View)
	}
}

func broadcast(path string, data any) {
	body, _ := json.Marshal(data)
	nodes := append(peersSnapshot(), self)
	for _, node := range nodes {
		go http.Post("http://"+node+path, "application/json", bytes.NewReader(body))
	}
}
