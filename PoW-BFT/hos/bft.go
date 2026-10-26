package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var consensusInProgress atomic.Bool

var pbftHTTPClient = &http.Client{Timeout: 3 * time.Second}

const (
	PhaseIdle int32 = iota
	PhasePrePrepare
	PhasePrepare
	PhaseCommit
	PhaseFinal
	ConsensusBatchSize  = 200
	ConsensusTimeout    = 10
	PBFTProgressTimeout = 4 * time.Second
)

type voteCollector struct {
	votes map[string]string
}

func newCollector() *voteCollector {
	return &voteCollector{votes: make(map[string]string)}
}

func (c *voteCollector) add(addr, sig string) bool {
	if _, exists := c.votes[addr]; exists {
		return false
	}
	c.votes[addr] = sig
	return true
}

func (c *voteCollector) count() int {
	return len(c.votes)
}

func (c *voteCollector) signedVotes() []PBFTSignature {
	voters := make([]string, 0, len(c.votes))
	for voter := range c.votes {
		voters = append(voters, voter)
	}
	sort.Strings(voters)
	votes := make([]PBFTSignature, 0, len(voters))
	for _, voter := range voters {
		votes = append(votes, PBFTSignature{Voter: voter, Signature: c.votes[voter]})
	}
	return votes
}

type viewState struct {
	mu             sync.Mutex
	Phase          int32
	Block          LowerBlock
	Prepare        *voteCollector
	Commit         *voteCollector
	Leader         string
	Participants   []string
	StartedAt      time.Time
	LastProgress   time.Time
	Proposal       bftStartMessage
	PendingPrepare []bftVoteMessage
	PendingCommit  []bftVoteMessage
	Finalized      bool
}

type bftStartMessage struct {
	View         int        `json:"view"`
	Block        LowerBlock `json:"block"`
	Leader       string     `json:"leader"`
	Participants []string   `json:"participants"`
	Signature    string     `json:"signature"`
}

type bftVoteMessage struct {
	View int    `json:"view"`
	Addr string `json:"addr"`
	Sig  string `json:"sig"`
	Hash string `json:"hash"`
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

// 고정된 합의 참여 노드 수를 기준으로 BFT 정족수 계산
// n >= 3f+1, f=floor((n-1)/3) 조건에서 n-f를 사용하면
// 서로 다른 두 정족수는 최소 f+1개의 노드를 공유함
func quorumSizeFor(n int) int {
	if n <= 0 {
		return 0
	}
	f := (n - 1) / 3
	return n - f
}

func consensusParticipants() []string {
	set := map[string]struct{}{self: {}}
	for _, peer := range peersSnapshot() {
		if peer != "" {
			set[peer] = struct{}{}
		}
	}
	participants := make([]string, 0, len(set))
	for participant := range set {
		participants = append(participants, participant)
	}
	sort.Strings(participants)
	return participants
}

func sameStringList(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func isSortedUnique(items []string) bool {
	if len(items) == 0 {
		return false
	}
	for i := 1; i < len(items); i++ {
		if items[i-1] >= items[i] {
			return false
		}
	}
	return true
}

func containsParticipant(participants []string, participant string) bool {
	index := sort.SearchStrings(participants, participant)
	return index < len(participants) && participants[index] == participant
}

func pbftVoteDigest(hosID string, view int, phase int32, blockHash, leader string, participants []string) []byte {
	membership := sha256.Sum256([]byte(strings.Join(participants, "\x00")))
	payload := fmt.Sprintf("PBFT|v1|%s|%d|%d|%s|%s|%x", hosID, view, phase, blockHash, leader, membership)
	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

func signPBFTVote(privateKey string, hosID string, view int, phase int32, blockHash, leader string, participants []string) string {
	digest := pbftVoteDigest(hosID, view, phase, blockHash, leader, participants)
	return makeAnchorSignature(privateKey, hex.EncodeToString(digest), "")
}

func pbftPublicKeyFor(address string) (string, bool) {
	if address == self {
		return getMeta("meta_hos_pubkey")
	}
	pkMu.RLock()
	defer pkMu.RUnlock()
	key, ok := peerPubKeys[address]
	return key, ok && key != ""
}

func verifyPBFTVote(vote bftVoteMessage, phase int32, block LowerBlock, leader string, participants []string) bool {
	if vote.View != block.Index || vote.Hash != block.BlockHash ||
		!containsParticipant(participants, vote.Addr) {
		return false
	}
	publicKey, ok := pbftPublicKeyFor(vote.Addr)
	if !ok {
		return false
	}
	digest := pbftVoteDigest(block.HosID, vote.View, phase, vote.Hash, leader, participants)
	return verifyECDSA(publicKey, digest, vote.Sig)
}

func startConsensusWatcher() {
	ticker := time.NewTicker(time.Second)
	var lastConsensusTime time.Time // 초기화를 하지 않음

	for range ticker.C {
		if self != boot {
			continue
		}
		if consensusInProgress.Load() {
			retryPBFTConsensus()
			continue
		}

		pendingCnt := getPendingCnt()
		if pendingCnt == 0 {
			lastConsensusTime = time.Time{} // 데이터 없으면 시간 리셋
			continue
		}

		// 첫 데이터가 들어왔을 때 기준 시간 설정
		if lastConsensusTime.IsZero() {
			lastConsensusTime = time.Now()
		}

		// 메모리풀의 엔트리 수가 임계값 이상이거나, 마지막 합의 시점부터 임계대기시간 이후로 지났을 때 합의 수행
		timeSinceLastConsensus := time.Since(lastConsensusTime)
		shouldStart := pendingCnt >= ConsensusBatchSize || timeSinceLastConsensus >= ConsensusTimeout*time.Second

		reason := "Timeout"
		// 합의 이유(Reason) 결정
		if pendingCnt >= ConsensusBatchSize {
			reason = "Full-Batch"
		}

		if !shouldStart {
			// 아직 조건 미달이므로 대기
			continue
		}
		records := popPending()
		// 그사이 비워졌을 경우를 대비한 방어 로직
		if len(records) == 0 {
			continue
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
		participants := consensusParticipants()
		vs.Block = block
		vs.Leader = self
		vs.Participants = append([]string(nil), participants...)
		vs.StartedAt = time.Now()
		vs.LastProgress = vs.StartedAt
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

		// Pre-Prepare도 서명하여 리더가 만든 제안인지 검증할 수 있게 한다.
		privateKey, ok := getMeta("meta_hos_privkey")
		if !ok {
			log.Printf("[PBFT][시작 오류] 리더 개인키가 없습니다")
			consensusInProgress.Store(false)
			continue
		}
		proposal := bftStartMessage{
			View: view, Block: block, Leader: self, Participants: participants,
			Signature: signPBFTVote(privateKey, block.HosID, view, PhasePrePrepare, block.BlockHash, self, participants),
		}
		vs.mu.Lock()
		vs.Proposal = proposal
		vs.mu.Unlock()
		broadcast("/bft/start", proposal, participants)

		// 마지막 합의 시간 갱신 (반드시 루프 마지막이나 시작 시점에 갱신 확인)
		lastConsensusTime = time.Now()
	}
}

func handleBftStart(w http.ResponseWriter, r *http.Request) {
	var msg bftStartMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Pre-Prepare JSON 형식이 올바르지 않습니다", http.StatusBadRequest)
		return
	}
	if err := validateBFTStart(msg); err != nil {
		log.Printf("[PBFT][PRE-PREPARE 거부] 뷰=%d: %v", msg.View, err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	vs := getOrCreateView(msg.View)
	vs.mu.Lock()
	if vs.Phase != PhaseIdle && (vs.Block.BlockHash != msg.Block.BlockHash || vs.Leader != msg.Leader ||
		!sameStringList(vs.Participants, msg.Participants)) {
		vs.mu.Unlock()
		http.Error(w, "현재 뷰의 제안과 다른 Pre-Prepare입니다", http.StatusConflict)
		return
	}
	if vs.Phase != PhaseIdle && vs.Phase != PhasePrePrepare {
		phase := vs.Phase
		prepareSig := vs.Prepare.votes[self]
		commitSig := vs.Commit.votes[self]
		participants := append([]string(nil), vs.Participants...)
		blockHash := vs.Block.BlockHash
		vs.mu.Unlock()
		if phase == PhasePrepare && prepareSig != "" {
			broadcast("/bft/prepare", bftVoteMessage{View: msg.View, Addr: self, Sig: prepareSig, Hash: blockHash}, participants)
		}
		if phase >= PhaseCommit && commitSig != "" {
			broadcast("/bft/commit", bftVoteMessage{View: msg.View, Addr: self, Sig: commitSig, Hash: blockHash}, participants)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	vs.Block = msg.Block
	vs.Leader = msg.Leader
	vs.Participants = append([]string(nil), msg.Participants...)
	vs.Proposal = msg
	if vs.StartedAt.IsZero() {
		vs.StartedAt = time.Now()
	}
	vs.Phase = PhasePrepare
	vs.LastProgress = time.Now()

	myPriv, ok := getMeta("meta_hos_privkey")
	if !ok {
		vs.mu.Unlock()
		http.Error(w, "노드 개인키가 없습니다", http.StatusInternalServerError)
		return
	}
	sig := signPBFTVote(myPriv, vs.Block.HosID, msg.View, PhasePrepare, vs.Block.BlockHash, vs.Leader, vs.Participants)
	vs.Prepare.add(self, sig)
	pendingPrepare := append([]bftVoteMessage(nil), vs.PendingPrepare...)
	pendingCommit := append([]bftVoteMessage(nil), vs.PendingCommit...)
	vs.PendingPrepare = nil
	vs.PendingCommit = nil
	participants := append([]string(nil), vs.Participants...)
	blockHash := vs.Block.BlockHash
	vs.mu.Unlock()

	log.Printf("[PBFT][PREPARE] Send Prepare for View %d", msg.View)
	broadcast("/bft/prepare", bftVoteMessage{View: msg.View, Addr: self, Sig: sig, Hash: blockHash}, participants)
	processBufferedPBFTVotes(vs, msg.View, pendingPrepare, pendingCommit)
}

func validateBFTStart(msg bftStartMessage) error {
	if msg.View <= 0 || msg.Leader == "" || msg.Block.BlockHash == "" || msg.Signature == "" {
		return fmt.Errorf("Pre-Prepare 필수 정보가 비어 있습니다")
	}
	if msg.Block.ConsensusVersion != PBFTConsensusVersion {
		return fmt.Errorf("새 PBFT 제안은 합의 버전 %d이어야 합니다", PBFTConsensusVersion)
	}
	if msg.Leader != boot || msg.Block.Proposer != msg.Leader || msg.Block.Index != msg.View {
		return fmt.Errorf("Pre-Prepare 리더, 제안자 또는 뷰가 올바르지 않습니다")
	}
	if !isSortedUnique(msg.Participants) || !containsParticipant(msg.Participants, msg.Leader) ||
		!containsParticipant(msg.Participants, self) {
		return fmt.Errorf("Pre-Prepare 참여자 스냅샷이 올바르지 않습니다")
	}
	if !sameStringList(msg.Participants, consensusParticipants()) {
		return fmt.Errorf("Pre-Prepare 참여자 스냅샷이 현재 검증자 집합과 다릅니다")
	}
	chainMu.Lock()
	previous, err := getBlockByIndex(msg.Block.Index - 1)
	if err == nil {
		err = validateLowerBlockStructure(msg.Block, previous)
	}
	chainMu.Unlock()
	if err != nil {
		return fmt.Errorf("제안 블록 구조 검증 실패: %w", err)
	}
	publicKey, ok := pbftPublicKeyFor(msg.Leader)
	if !ok {
		return fmt.Errorf("PBFT 리더 공개키를 찾을 수 없습니다")
	}
	digest := pbftVoteDigest(msg.Block.HosID, msg.View, PhasePrePrepare, msg.Block.BlockHash, msg.Leader, msg.Participants)
	if !verifyECDSA(publicKey, digest, msg.Signature) {
		return fmt.Errorf("Pre-Prepare 리더 서명이 유효하지 않습니다")
	}
	return nil
}

func handleReceivePrepare(w http.ResponseWriter, r *http.Request) {
	var msg bftVoteMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		return
	}

	if err := processPBFTVote(msg, PhasePrepare); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func handleReceiveCommit(w http.ResponseWriter, r *http.Request) {
	var msg bftVoteMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		return
	}

	if err := processPBFTVote(msg, PhaseCommit); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// processPBFTVote는 Pre-Prepare보다 먼저 도착한 투표를 버리지 않고 보관하며,
// ECDSA 검증은 뷰 잠금 밖에서 수행한 뒤 상태가 바뀌지 않았는지 다시 확인한다.
func processPBFTVote(msg bftVoteMessage, phase int32) error {
	vs := getOrCreateView(msg.View)
	vs.mu.Lock()
	if vs.Block.BlockHash == "" {
		if phase == PhasePrepare {
			vs.PendingPrepare = append(vs.PendingPrepare, msg)
		} else {
			vs.PendingCommit = append(vs.PendingCommit, msg)
		}
		vs.mu.Unlock()
		return nil
	}
	if phase == PhaseCommit && vs.Phase < PhaseCommit {
		vs.PendingCommit = append(vs.PendingCommit, msg)
		vs.mu.Unlock()
		return nil
	}
	block := vs.Block
	leader := vs.Leader
	participants := append([]string(nil), vs.Participants...)
	vs.mu.Unlock()

	if !verifyPBFTVote(msg, phase, block, leader, participants) {
		return fmt.Errorf("PBFT %d단계 투표 서명이 유효하지 않습니다", phase)
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()
	if vs.Block.BlockHash != block.BlockHash || vs.Leader != leader || !sameStringList(vs.Participants, participants) {
		return fmt.Errorf("투표 검증 중 PBFT 뷰 상태가 변경되었습니다")
	}
	collector := vs.Prepare
	if phase == PhaseCommit {
		collector = vs.Commit
	}
	if collector.add(msg.Addr, msg.Sig) {
		vs.LastProgress = time.Now()
	}
	if phase == PhasePrepare {
		advancePBFTToCommit(vs, msg.View)
	} else {
		finalizePBFTIfReady(vs, msg.View)
	}
	return nil
}

func processBufferedPBFTVotes(vs *viewState, view int, prepares, commits []bftVoteMessage) {
	for _, vote := range prepares {
		if err := processPBFTVote(vote, PhasePrepare); err != nil {
			log.Printf("[PBFT][PREPARE 보관 투표 거부] 뷰=%d: %v", view, err)
		}
	}
	for _, vote := range commits {
		if err := processPBFTVote(vote, PhaseCommit); err != nil {
			log.Printf("[PBFT][COMMIT 보관 투표 거부] 뷰=%d: %v", view, err)
		}
	}
}

// retryPBFTConsensus는 일시적인 전송 실패로 합의가 영구 정지하지 않도록
// 동일한 서명 제안을 재전파한다. 수신 노드는 현재 단계의 투표만 다시 보낸다.
func retryPBFTConsensus() {
	height, ok := getLatestHeight()
	if !ok {
		return
	}
	vs := getOrCreateView(height + 1)
	vs.mu.Lock()
	if vs.Finalized || vs.Proposal.Block.BlockHash == "" || time.Since(vs.LastProgress) < PBFTProgressTimeout {
		vs.mu.Unlock()
		return
	}
	proposal := vs.Proposal
	participants := append([]string(nil), vs.Participants...)
	vs.LastProgress = time.Now()
	vs.mu.Unlock()
	log.Printf("[PBFT][재전송] 뷰=%d에서 진행이 없어 서명된 Pre-Prepare를 다시 전파합니다.", proposal.View)
	broadcast("/bft/start", proposal, participants)
}

// advancePBFTToCommit은 Prepare 정족수가 충족된 경우 한 번만 Commit 투표를 시작한다.
func advancePBFTToCommit(vs *viewState, view int) {
	if vs.Prepare.count() < quorumSizeFor(len(vs.Participants)) || vs.Phase != PhasePrepare {
		return
	}
	vs.Phase = PhaseCommit
	privateKey, ok := getMeta("meta_hos_privkey")
	if !ok {
		log.Printf("[PBFT][COMMIT 오류] 노드 개인키가 없습니다")
		return
	}
	signature := signPBFTVote(privateKey, vs.Block.HosID, view, PhaseCommit, vs.Block.BlockHash, vs.Leader, vs.Participants)
	vs.Commit.add(self, signature)
	pendingCommit := append([]bftVoteMessage(nil), vs.PendingCommit...)
	vs.PendingCommit = nil
	log.Printf("[PBFT][COMMIT] Prepare 정족수 충족. 뷰 %d의 Commit을 전파합니다.", view)
	broadcast("/bft/commit", bftVoteMessage{View: view, Addr: self, Sig: signature, Hash: vs.Block.BlockHash}, vs.Participants)
	finalizePBFTIfReady(vs, view)
	if len(pendingCommit) > 0 {
		go processBufferedPBFTVotes(vs, view, nil, pendingCommit)
	}
}

// finalizePBFTIfReady는 Commit 정족수가 충족된 블록을 한 번만 확정하고 저장한다.
func finalizePBFTIfReady(vs *viewState, view int) {
	if vs.Commit.count() >= quorumSizeFor(len(vs.Participants)) && !vs.Finalized {
		vs.Finalized = true
		vs.Phase = PhaseFinal
		commitVotes := vs.Commit.signedVotes()
		vs.Block.Signatures = make([]string, 0, len(commitVotes))
		for _, vote := range commitVotes {
			vs.Block.Signatures = append(vs.Block.Signatures, vote.Signature)
		}
		vs.Block.PBFT = &PBFTProof{
			View: view, Leader: vs.Leader,
			Participants: append([]string(nil), vs.Participants...), CommitVotes: commitVotes,
		}
		vs.Block.Elapsed = float32(time.Since(vs.StartedAt).Seconds())

		log.Printf("[PBFT][FINALIZED] View %d Finalized. Saving to DB...", view)

		// [중요] 체인 저장 함수 호출
		if err := onVerifiedBlockReceived(vs.Block); err != nil {
			log.Printf("[PBFT][FINALIZED 오류] 뷰=%d 블록 저장 실패: %v", view, err)
			vs.Finalized = false
			vs.Phase = PhaseCommit
			vs.LastProgress = time.Now()
			return
		}

		deleteView(view)
	}
}

func broadcast(path string, data any, participants []string) {
	body, err := json.Marshal(data)
	if err != nil {
		log.Printf("[PBFT][직렬화 오류] %s 메시지 생성 실패: %v", path, err)
		return
	}
	for _, node := range participants {
		node := node
		go func() {
			response, err := pbftHTTPClient.Post("http://"+node+path, "application/json", bytes.NewReader(body))
			if err != nil {
				log.Printf("[PBFT][네트워크 오류] %s%s 전송 실패: %v", node, path, err)
				return
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, response.Body)
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				log.Printf("[PBFT][네트워크 오류] %s%s 응답 상태=%d", node, path, response.StatusCode)
			}
		}()
	}
}
