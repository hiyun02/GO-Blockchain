package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// BFT 합의 수집기 (Prepare/Commit 단계별로 별도 관리)
type consensusCollector struct {
	mu         sync.Mutex
	signatures []string
	votedPeers map[string]bool
}

var (
	prepareCollector *consensusCollector
	commitCollector  *consensusCollector
	collectorMu      sync.Mutex
	currentBlock     LowerBlock // 현재 합의 중인 블록 임시 저장
)

// 1. WATCHER: 리더가 블록을 제안 (Pre-Prepare)
func startMiningWatcher() {
	t := time.NewTicker(time.Duration(ConsWatcherTime) * time.Second)
	for range t.C {
		if ConsPhase.Load() != ConsIdle || pendingIsEmpty() {
			continue
		}
		if self != boot { // 리더(부트노드)만 제안
			continue
		}

		records := getPending()
		ConsPhase.Store(ConsPrePrepare)

		// 블록 생성 및 리더 서명
		newBlock := createProposedBlock(records)
		currentBlock = newBlock

		// 콜렉터 초기화
		initCollectors()

		log.Printf("[BFT-LEADER] Phase: Pre-Prepare | Index: %d", newBlock.Index)
		broadcastToAll("/bft/start", newBlock)
	}
}

// 2. NODE: 리더의 제안을 받고 검증 신호 전파 (Prepare)
func handleBftStart(w http.ResponseWriter, r *http.Request) {
	var lb LowerBlock
	json.NewDecoder(r.Body).Decode(&lb)

	// 단계 보호 및 검증
	if !ConsPhase.CompareAndSwap(ConsIdle, ConsPrepare) {
		return
	}

	height, _ := getLatestHeight()
	prev, _ := getBlockByIndex(height)
	if err := validateLowerBlock(lb, prev); err != nil {
		ConsPhase.Store(ConsIdle)
		return
	}

	currentBlock = lb // 검증된 블록 저장
	myPriv, _ := getMeta("meta_hos_privkey")
	mySig := makeAnchorSignature(myPriv, lb.BlockHash, "")

	log.Printf("[BFT-NODE] Phase: Prepare | Index: %d", lb.Index)
	// 모든 노드에게 "나 이 블록 준비됐어"라고 Prepare 신호 전파
	broadcastToAll("/bft/prepare", map[string]string{"addr": self, "sig": mySig})
	w.WriteHeader(http.StatusOK)
}

// 3. NODE/LEADER: Prepare 서명 수집 및 Commit 전파
func handleReceivePrepare(w http.ResponseWriter, r *http.Request) {
	var msg struct{ Addr, Sig string }
	json.NewDecoder(r.Body).Decode(&msg)

	if addVote(prepareCollector, msg.Addr, msg.Sig) {
		if checkQuorum(prepareCollector) && ConsPhase.Load() == ConsPrepare {
			ConsPhase.Store(ConsCommit)

			myPriv, _ := getMeta("meta_hos_privkey")
			mySig := makeAnchorSignature(myPriv, currentBlock.BlockHash, "")

			log.Printf("[BFT-NODE] Phase: Commit | Quorum reached")
			// 정족수 채워지면 "진짜 합의하자"고 Commit 신호 전파
			broadcastToAll("/bft/commit", map[string]string{"addr": self, "sig": mySig})
		}
	}
}

// 4. NODE/LEADER: Commit 서명 수집 및 최종 장부 기록
func handleReceiveCommit(w http.ResponseWriter, r *http.Request) {
	var msg struct{ Addr, Sig string }
	json.NewDecoder(r.Body).Decode(&msg)

	if addVote(commitCollector, msg.Addr, msg.Sig) {
		if checkQuorum(commitCollector) && ConsPhase.Load() == ConsCommit {
			log.Printf("[BFT-SUCCESS] Consensus Reached for Block #%d", currentBlock.Index)

			// 최종 수집된 서명들을 블록에 담아 저장
			currentBlock.Signatures = commitCollector.signatures
			onBlockReceived(currentBlock)

			ConsPhase.Store(ConsIdle) // 합의 종료 및 대기상태 복귀
		}
	}
}

// --- 헬퍼 함수들 ---

func initCollectors() {
	collectorMu.Lock()
	defer collectorMu.Unlock()
	prepareCollector = &consensusCollector{votedPeers: make(map[string]bool)}
	commitCollector = &consensusCollector{votedPeers: make(map[string]bool)}
}

func addVote(c *consensusCollector, addr string, sig string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.votedPeers[addr] {
		return false
	}
	c.signatures = append(c.signatures, sig)
	c.votedPeers[addr] = true
	return true
}

func checkQuorum(c *consensusCollector) bool {
	n := len(peersSnapshot()) + 1
	return len(c.signatures) >= (2*(n-1)/3 + 1)
}

func broadcastToAll(path string, data any) {
	body, _ := json.Marshal(data)
	nodes := append(peersSnapshot(), self) // 나 포함 전체 전파
	for _, node := range nodes {
		go http.Post("http://"+node+path, "application/json", bytes.NewReader(body))
	}
}

// 리더가 새로운 후보 블록을 생성하는 함수
func createProposedBlock(entries []ClinicRecord) LowerBlock {
	height, _ := getLatestHeight()          //
	prevBlock, _ := getBlockByIndex(height) //

	newBlock := LowerBlock{
		Index:      height + 1,
		HosID:      selfID(), //
		PrevHash:   prevBlock.BlockHash,
		Timestamp:  time.Now().Format(time.RFC3339),
		Entries:    entries,
		Proposer:   self,
		Signatures: []string{}, // 아직 다른 노드 서명은 없음
	}

	// 머클루트 계산 및 블록 해시 생성
	leafHashes := make([]string, len(entries))
	for i, r := range entries {
		leafHashes[i] = hashClinicRecord(r)
	}
	newBlock.MerkleRoot = merkleRootHex(leafHashes)
	newBlock.LeafHashes = leafHashes
	newBlock.BlockHash = newBlock.computeHash() //

	// 리더(자신)의 서명 생성하여 추가
	myPriv, _ := getMeta("meta_hos_privkey")                     //
	mySig := makeAnchorSignature(myPriv, newBlock.BlockHash, "") //
	newBlock.Signatures = append(newBlock.Signatures, mySig)

	return newBlock
}
