package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// Gov BFT 합의 수집기 (AnchorRecord 기반)
type consensusCollector struct {
	mu         sync.Mutex
	signatures []string
	votedPeers map[string]bool
}

var (
	prepareCollector *consensusCollector
	commitCollector  *consensusCollector
	collectorMu      sync.Mutex
	currentBlock     UpperBlock //
)

// 1. WATCHER: 수집된 앵커(Pending)가 있으면 리더가 제안 시작 (Pre-Prepare)
func startMiningWatcher() {
	t := time.NewTicker(time.Duration(ConsWatcherTime) * time.Second) //
	log.Printf("[BFT-WATCHER] Gov Consensus Watcher Started")

	for range t.C {
		// 현재 합의 중이거나 수집된 앵커가 없으면 스킵
		if ConsPhase.Load() != ConsIdle || pendingIsEmpty() { //
			continue
		}

		// Gov 체인의 부트노드가 리더 역할을 수행
		if self != boot {
			continue
		}

		// anchor.go의 addAnchor를 통해 쌓인 AnchorRecord들을 가져옴
		records := getPending() //
		log.Printf("[BFT-LEADER] Pending Anchors detected => Proposing UpperBlock (records: %d)", len(records))

		ConsPhase.Store(ConsPrePrepare) //

		// UpperBlock 생성 및 리더 서명
		newBlock := createProposedBlock(records)
		currentBlock = newBlock

		initCollectors()

		// 모든 Gov 노드에 Pre-Prepare 알림 전파
		broadcastToAll("/bft/start", newBlock)
	}
}

// 2. NODE: 리더의 제안(UpperBlock)을 받고 검증 후 신호 전파 (Prepare)
func handleBftStart(w http.ResponseWriter, r *http.Request) {
	var ub UpperBlock
	if err := json.NewDecoder(r.Body).Decode(&ub); err != nil {
		return
	}

	// 단계 보호 및 Gov 체인 연결성 검증
	if !ConsPhase.CompareAndSwap(ConsIdle, ConsPrepare) {
		return
	}

	height, _ := getLatestHeight()     //
	prev, _ := getBlockByIndex(height) //

	// Gov 체인용 검증 로직 (Index, PrevHash 등 확인)
	if ub.Index != prev.Index+1 || ub.PrevHash != prev.BlockHash {
		log.Printf("[BFT-VALIDATE] Gov Block Sequence Error")
		ConsPhase.Store(ConsIdle)
		return
	}

	currentBlock = ub
	myPriv, _ := getMeta("meta_hos_privkey")               // Gov 노드 개인키 로드
	mySig := makeAnchorSignature(myPriv, ub.BlockHash, "") //

	log.Printf("[BFT-NODE] Phase: Prepare | Gov Index: %d", ub.Index)
	broadcastToAll("/bft/prepare", map[string]string{"addr": self, "sig": mySig})
	w.WriteHeader(http.StatusOK)
}

// 3. NODE/LEADER: Prepare 서명 수집 및 Commit 전파
func handleReceivePrepare(w http.ResponseWriter, r *http.Request) {
	var msg struct{ Addr, Sig string }
	json.NewDecoder(r.Body).Decode(&msg)

	if addVote(prepareCollector, msg.Addr, msg.Sig) {
		// Gov 노드들 사이의 정족수(2f+1) 확인
		if checkQuorum(prepareCollector) && ConsPhase.Load() == ConsPrepare {
			ConsPhase.Store(ConsCommit)

			myPriv, _ := getMeta("meta_hos_privkey")
			mySig := makeAnchorSignature(myPriv, currentBlock.BlockHash, "")

			log.Printf("[BFT-NODE] Phase: Commit | Gov Quorum reached")
			broadcastToAll("/bft/commit", map[string]string{"addr": self, "sig": mySig})
		}
	}
}

// 4. NODE/LEADER: Commit 서명 수집 및 최종 상위 장부 기록
func handleReceiveCommit(w http.ResponseWriter, r *http.Request) {
	var msg struct{ Addr, Sig string }
	json.NewDecoder(r.Body).Decode(&msg)

	if addVote(commitCollector, msg.Addr, msg.Sig) {
		if checkQuorum(commitCollector) && ConsPhase.Load() == ConsCommit {
			log.Printf("[BFT-SUCCESS] Gov Consensus Finalized for Block #%d", currentBlock.Index)

			// 최종 서명 목록 업데이트 및 저장
			currentBlock.Signatures = commitCollector.signatures
			onBlockReceived(currentBlock) //

			ConsPhase.Store(ConsIdle)
		}
	}
}

// --- Gov 전용 헬퍼 함수 ---

func createProposedBlock(records []AnchorRecord) UpperBlock {
	height, _ := getLatestHeight()
	prevBlock, _ := getBlockByIndex(height)

	ub := UpperBlock{
		Index:      height + 1,
		GovID:      selfID(), //
		PrevHash:   prevBlock.BlockHash,
		Timestamp:  time.Now().Format(time.RFC3339),
		Records:    records, // 하위체인에서 온 앵커들을 담음
		Proposer:   self,
		Signatures: []string{},
	}

	// 앵커들의 루트를 다시 Merkle Tree로 구성하여 상위 루트 계산
	leafHashes := make([]string, len(records))
	for i, r := range records {
		leafHashes[i] = sha256Hex([]byte(r.LowerRoot)) // 앵커 루트들을 리프로 사용
	}
	ub.MerkleRoot = merkleRootHex(leafHashes)
	ub.BlockHash = ub.computeHash() //

	// 리더 서명 추가
	myPriv, _ := getMeta("meta_hos_privkey")
	mySig := makeAnchorSignature(myPriv, ub.BlockHash, "")
	ub.Signatures = append(ub.Signatures, mySig)

	return ub
}

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
	nodes := append(peersSnapshot(), self)
	for _, node := range nodes {
		go http.Post("http://"+node+path, "application/json", bytes.NewReader(body))
	}
}
