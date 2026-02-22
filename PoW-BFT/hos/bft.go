package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

//////////////////////////////////////////////////
// PBFT STATE STRUCTURES
//////////////////////////////////////////////////

type consensusCollector struct {
	mu         sync.Mutex
	signatures map[string]string
}

func newCollector() *consensusCollector {
	return &consensusCollector{
		signatures: make(map[string]string),
	}
}

type viewState struct {
	mu               sync.Mutex
	Phase            int32
	Block            LowerBlock
	PrepareCollector *consensusCollector
	CommitCollector  *consensusCollector
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
			Phase:            ConsIdle,
			PrepareCollector: newCollector(),
			CommitCollector:  newCollector(),
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
// WATCHER (LEADER ONLY)
//////////////////////////////////////////////////

func startConsensWatcher() {

	t := time.NewTicker(time.Duration(ConsWatcherTime) * time.Second)
	log.Printf("[WATCHER] PBFT Watcher Started")

	for range t.C {

		if self != boot {
			continue
		}

		// 🔒 글로벌 합의 중이면 시작 금지
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
		if vs.Phase != ConsIdle {
			vs.mu.Unlock()
			continue
		}

		block := createProposedBlock(records)
		vs.Block = block
		vs.Phase = ConsPrePrepare
		vs.mu.Unlock()

		// 🔒 합의 시작 플래그 ON
		consensusInProgress.Store(true)

		log.Printf("[BFT-LEADER] PrePrepare | view=%d | records=%d", view, len(records))

		broadcastToAll("/bft/start", struct {
			View  int
			Block LowerBlock
		}{view, block})
	}
}

//////////////////////////////////////////////////
// PRE-PREPARE → PREPARE
//////////////////////////////////////////////////

func handleBftStart(w http.ResponseWriter, r *http.Request) {

	var msg struct {
		View  int
		Block LowerBlock
	}
	json.NewDecoder(r.Body).Decode(&msg)

	vs := getOrCreateView(msg.View)

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.Phase != ConsIdle {
		return
	}

	height, _ := getLatestHeight()
	prev, _ := getBlockByIndex(height)

	if err := validateLowerBlock(msg.Block, prev); err != nil {
		return
	}

	vs.Block = msg.Block
	vs.Phase = ConsPrepare

	myPriv, _ := getMeta("meta_hos_privkey")
	sig := makeAnchorSignature(myPriv, msg.Block.BlockHash, "")

	// 자기 prepare 직접 추가 (안전)
	addVote(vs.PrepareCollector, self, sig)

	log.Printf("[BFT-NODE] Prepare | view=%d", msg.View)

	broadcastToAll("/bft/prepare", struct {
		View int
		Addr string
		Sig  string
		Hash string
	}{
		msg.View,
		self,
		sig,
		msg.Block.BlockHash,
	})
}

//////////////////////////////////////////////////
// PREPARE → COMMIT
//////////////////////////////////////////////////

func handleReceivePrepare(w http.ResponseWriter, r *http.Request) {

	var msg struct {
		View int
		Addr string
		Sig  string
		Hash string
	}
	json.NewDecoder(r.Body).Decode(&msg)

	vs := getOrCreateView(msg.View)

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.Block.BlockHash != msg.Hash {
		return
	}

	if !addVote(vs.PrepareCollector, msg.Addr, msg.Sig) {
		return
	}

	if checkQuorum(vs.PrepareCollector) && vs.Phase == ConsPrepare {

		vs.Phase = ConsCommit

		myPriv, _ := getMeta("meta_hos_privkey")
		sig := makeAnchorSignature(myPriv, vs.Block.BlockHash, "")

		// 자기 commit 직접 추가
		addVote(vs.CommitCollector, self, sig)

		log.Printf("[BFT] Commit broadcast | view=%d", msg.View)

		broadcastToAll("/bft/commit", struct {
			View int
			Addr string
			Sig  string
			Hash string
		}{
			msg.View,
			self,
			sig,
			vs.Block.BlockHash,
		})
	}
}

//////////////////////////////////////////////////
// COMMIT → FINALIZE
//////////////////////////////////////////////////

func handleReceiveCommit(w http.ResponseWriter, r *http.Request) {

	var msg struct {
		View int
		Addr string
		Sig  string
		Hash string
	}
	json.NewDecoder(r.Body).Decode(&msg)

	vs := getOrCreateView(msg.View)

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.Block.BlockHash != msg.Hash {
		return
	}

	if !addVote(vs.CommitCollector, msg.Addr, msg.Sig) {
		return
	}

	if checkQuorum(vs.CommitCollector) && vs.Phase == ConsCommit {

		vs.Phase = -1 // 🔒 finalize 상태

		for _, sig := range vs.CommitCollector.signatures {
			vs.Block.Signatures = append(vs.Block.Signatures, sig)
		}

		log.Printf("[BFT-SUCCESS] Block Finalized | view=%d", msg.View)

		onBlockReceived(vs.Block)

		deleteView(msg.View)
	}
}

//////////////////////////////////////////////////
// HELPERS
//////////////////////////////////////////////////

func addVote(c *consensusCollector, addr, sig string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.signatures[addr]; exists {
		return false
	}
	c.signatures[addr] = sig
	return true
}

func checkQuorum(c *consensusCollector) bool {
	n := len(peersSnapshot()) + 1
	required := (2*(n-1))/3 + 1

	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.signatures) >= required
}

func broadcastToAll(path string, data any) {
	body, _ := json.Marshal(data)
	nodes := append(peersSnapshot(), self)

	for _, node := range nodes {
		go http.Post("http://"+node+path, "application/json", bytes.NewReader(body))
	}
}
