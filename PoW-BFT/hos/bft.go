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

//////////////////////////////////////////////////
// GLOBAL CONSENSUS FLAG
//////////////////////////////////////////////////

var consensusInProgress atomic.Bool

//////////////////////////////////////////////////
// PBFT STATE
//////////////////////////////////////////////////

const (
	PhaseIdle int32 = iota
	PhasePrePrepare
	PhasePrepare
	PhaseCommit
	PhaseFinal
)

type voteCollector struct {
	mu    sync.Mutex
	votes map[string]string // addr -> signature
}

func newCollector() *voteCollector {
	return &voteCollector{
		votes: make(map[string]string),
	}
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
		vs = &viewState{
			Phase:   PhaseIdle,
			Prepare: newCollector(),
			Commit:  newCollector(),
		}
		viewStates[view] = vs
	}
	return vs
}

func deleteView(view int) {
	viewMu.Lock()
	defer viewMu.Unlock()
	delete(viewStates, view)
}

//////////////////////////////////////////////////
// QUORUM CALCULATION (3f+1, need 2f+1)
//////////////////////////////////////////////////

func quorumSize() int {
	n := len(peersSnapshot()) + 1 // self 포함
	f := (n - 1) / 3
	return 2*f + 1
}

//////////////////////////////////////////////////
// WATCHER (LEADER ONLY)
//////////////////////////////////////////////////

func startConsensusWatcher() {

	ticker := time.NewTicker(time.Second)
	log.Printf("[PBFT] Watcher started")

	for range ticker.C {

		if self != boot {
			continue
		}

		if consensusInProgress.Load() {
			continue
		}

		if pendingIsEmpty() {
			continue
		}

		records := getPending()
		if len(records) == 0 {
			continue
		}

		height, _ := getLatestHeight()
		view := height + 1

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

		log.Printf("[PBFT][PRE-PREPARE] view=%d hash=%s entries=%d",
			view, block.BlockHash, len(block.Entries))

		broadcast("/bft/start", map[string]any{
			"view":  view,
			"block": block,
		})
	}
}

//////////////////////////////////////////////////
// PRE-PREPARE
//////////////////////////////////////////////////

func handleBftStart(w http.ResponseWriter, r *http.Request) {

	var msg struct {
		View  int        `json:"view"`
		Block LowerBlock `json:"block"`
	}

	json.NewDecoder(r.Body).Decode(&msg)

	vs := getOrCreateView(msg.View)

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.Phase != PhaseIdle {
		return
	}

	// BlockHash 재검증
	if msg.Block.computeHash() != msg.Block.BlockHash {
		log.Printf("[PBFT] invalid block hash")
		return
	}

	height, _ := getLatestHeight()
	prev, _ := getBlockByIndex(height)

	if err := validateLowerBlock(msg.Block, prev); err != nil {
		log.Printf("[PBFT] validateLowerBlock fail: %v", err)
		return
	}

	vs.Block = msg.Block
	vs.Phase = PhasePrepare

	myPriv, _ := getMeta("meta_hos_privkey")
	sig := makeAnchorSignature(myPriv, msg.Block.BlockHash, "")

	vs.Prepare.add(self, sig)

	log.Printf("[PBFT][PREPARE] send prepare view=%d", msg.View)

	broadcast("/bft/prepare", map[string]any{
		"view": msg.View,
		"addr": self,
		"sig":  sig,
		"hash": msg.Block.BlockHash,
	})
}

//////////////////////////////////////////////////
// PREPARE
//////////////////////////////////////////////////

func handleReceivePrepare(w http.ResponseWriter, r *http.Request) {

	var msg struct {
		View int    `json:"view"`
		Addr string `json:"addr"`
		Sig  string `json:"sig"`
		Hash string `json:"hash"`
	}

	json.NewDecoder(r.Body).Decode(&msg)

	vs := getOrCreateView(msg.View)

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.Block.BlockHash != msg.Hash {
		return
	}

	pub, ok := peerPubKeys[msg.Addr]
	if !ok {
		return
	}

	hashBytes, _ := hex.DecodeString(msg.Hash)

	if !verifyECDSA(pub, hashBytes, msg.Sig) {
		log.Printf("[PBFT] prepare signature invalid")
		return
	}

	if !vs.Prepare.add(msg.Addr, msg.Sig) {
		return
	}

	log.Printf("[PBFT][PREPARE] collected=%d/%d view=%d",
		vs.Prepare.count(), quorumSize(), msg.View)

	if vs.Prepare.count() >= quorumSize() && vs.Phase == PhasePrepare {

		vs.Phase = PhaseCommit

		myPriv, _ := getMeta("meta_hos_privkey")
		sig := makeAnchorSignature(myPriv, vs.Block.BlockHash, "")

		vs.Commit.add(self, sig)

		log.Printf("[PBFT][COMMIT] broadcast view=%d", msg.View)

		broadcast("/bft/commit", map[string]any{
			"view": msg.View,
			"addr": self,
			"sig":  sig,
			"hash": vs.Block.BlockHash,
		})
	}
}

//////////////////////////////////////////////////
// COMMIT
//////////////////////////////////////////////////

func handleReceiveCommit(w http.ResponseWriter, r *http.Request) {

	var msg struct {
		View int    `json:"view"`
		Addr string `json:"addr"`
		Sig  string `json:"sig"`
		Hash string `json:"hash"`
	}

	json.NewDecoder(r.Body).Decode(&msg)

	vs := getOrCreateView(msg.View)

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.Block.BlockHash != msg.Hash {
		return
	}

	pub, ok := peerPubKeys[msg.Addr]
	if !ok {
		return
	}

	hashBytes, _ := hex.DecodeString(msg.Hash)

	if !verifyECDSA(pub, hashBytes, msg.Sig) {
		log.Printf("[PBFT] commit signature invalid")
		return
	}

	if !vs.Commit.add(msg.Addr, msg.Sig) {
		return
	}

	log.Printf("[PBFT][COMMIT] collected=%d/%d view=%d",
		vs.Commit.count(), quorumSize(), msg.View)

	if vs.Commit.count() >= quorumSize() &&
		vs.Phase == PhaseCommit &&
		!vs.Finalized {

		vs.Phase = PhaseFinal
		vs.Finalized = true

		vs.Block.Signatures = vs.Commit.all()

		log.Printf("[PBFT][FINALIZED] view=%d hash=%s",
			msg.View, vs.Block.BlockHash)

		onBlockReceived(vs.Block)

		deleteView(msg.View)
		consensusInProgress.Store(false)
	}
}

//////////////////////////////////////////////////
// NETWORK
//////////////////////////////////////////////////

func broadcast(path string, data any) {

	body, _ := json.Marshal(data)

	nodes := append(peersSnapshot(), self)

	for _, node := range nodes {
		go http.Post("http://"+node+path,
			"application/json",
			bytes.NewReader(body))
	}
}
