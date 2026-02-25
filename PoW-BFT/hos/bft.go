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

var consensusInProgress atomic.Bool

const (
	PhaseIdle int32 = iota
	PhasePrePrepare
	PhasePrepare
	PhaseCommit
	PhaseFinal
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
	for range ticker.C {
		if self != boot || consensusInProgress.Load() || pendingIsEmpty() {
			continue
		}

		height, _ := getLatestHeight()
		view := height + 1

		records := getPending()
		if len(records) == 0 {
			continue
		}

		vs := getOrCreateView(view)
		vs.mu.Lock()
		if vs.Phase != PhaseIdle {
			vs.mu.Unlock()
			continue
		}

		block := createProposedBlock(records)
		vs.Block = block
		vs.Phase = PhasePrePrepare
		vs.mu.Unlock()

		consensusInProgress.Store(true)
		log.Printf("[PBFT][START] View=%d, Hash=%s", view, block.BlockHash)
		broadcast("/bft/start", map[string]any{"view": view, "block": block})
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
	defer vs.mu.Unlock()

	// [수정] msg.Block.BlockHash -> vs.Block.BlockHash로 수정
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

		// [수정] vs.Block.BlockHash를 사용하여 자신의 Commit 서명 생성
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

		go func() {
			time.Sleep(100 * time.Millisecond)
		}()
	}
}

func broadcast(path string, data any) {
	body, _ := json.Marshal(data)
	nodes := append(peersSnapshot(), self)
	for _, node := range nodes {
		go http.Post("http://"+node+path, "application/json", bytes.NewReader(body))
	}
}
