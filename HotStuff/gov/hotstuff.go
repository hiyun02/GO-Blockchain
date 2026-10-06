package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Basic HotStuff의 Prepare -> Pre-Commit -> Commit -> Decide 흐름을 구현한다.
// 각 단계는 n-f개의 서명으로 QC(Quorum Certificate)를 만들며,
// Commit QC를 수신한 노드만 블록을 최종 저장한다.

type HotStuffPhase string

const (
	PhasePrepare   HotStuffPhase = "PREPARE"
	PhasePreCommit HotStuffPhase = "PRE_COMMIT"
	PhaseCommit    HotStuffPhase = "COMMIT"
)

var (
	ConsensusBatchSize = envInt("HOTSTUFF_BATCH_SIZE", 1)
	ConsensusTimeout   = time.Duration(envInt("HOTSTUFF_BATCH_TIMEOUT_SEC", 2)) * time.Second
	ViewTimeout        = time.Duration(envInt("HOTSTUFF_VIEW_TIMEOUT_SEC", 8)) * time.Second

	consensusInProgress atomic.Bool
	currentView         atomic.Uint64
)

// HotStuffSignature는 동기화 노드가 서명 주체와 중복 여부를 검증할 수 있게 한다.
type HotStuffSignature struct {
	Voter     string `json:"voter"`
	Signature string `json:"signature"`
}

// QuorumCertificate는 특정 뷰/단계/블록에 대한 정족수 인증서다.
// Participants는 합의 도중 피어 수가 변해도 당시 정족수를 재현하는 스냅샷이다.
type QuorumCertificate struct {
	View         uint64              `json:"view"`
	Phase        HotStuffPhase       `json:"phase"`
	BlockHash    string              `json:"block_hash"`
	Leader       string              `json:"leader"`
	Participants []string            `json:"participants"`
	Signatures   []HotStuffSignature `json:"signatures"`
	CreatedAt    string              `json:"created_at"`
}

// HotStuffProof는 최종 블록에 포함되는 감사 가능한 3단계 합의 증거다.
type HotStuffProof struct {
	View        uint64            `json:"view"`
	PrepareQC   QuorumCertificate `json:"prepare_qc"`
	PreCommitQC QuorumCertificate `json:"pre_commit_qc"`
	CommitQC    QuorumCertificate `json:"commit_qc"`
}

type hotStuffProposal struct {
	View         uint64             `json:"view"`
	Leader       string             `json:"leader"`
	Block        UpperBlock         `json:"block"`
	Participants []string           `json:"participants"`
	Justify      *QuorumCertificate `json:"justify_qc,omitempty"`
}

type hotStuffVote struct {
	View      uint64        `json:"view"`
	Phase     HotStuffPhase `json:"phase"`
	BlockHash string        `json:"block_hash"`
	Voter     string        `json:"voter"`
	Signature string        `json:"signature"`
}

type hotStuffQCEnvelope struct {
	View         uint64              `json:"view"`
	Leader       string              `json:"leader"`
	Block        UpperBlock          `json:"block"`
	Certificates []QuorumCertificate `json:"certificates"`
}

type voteCollector struct {
	votes map[string]string
}

func newVoteCollector() *voteCollector {
	return &voteCollector{votes: make(map[string]string)}
}

func (c *voteCollector) add(voter, signature string) bool {
	if _, exists := c.votes[voter]; exists {
		return false
	}
	c.votes[voter] = signature
	return true
}

type hotStuffViewState struct {
	mu           sync.Mutex
	View         uint64
	Leader       string
	Block        UpperBlock
	Participants []string
	Collectors   map[HotStuffPhase]*voteCollector
	QCs          map[HotStuffPhase]QuorumCertificate
	Finalized    bool
	StartedAt    time.Time
}

var (
	hotStuffStates   = make(map[uint64]*hotStuffViewState)
	hotStuffStatesMu sync.Mutex

	safetyMu sync.Mutex
	highQC   *QuorumCertificate
	lockedQC *QuorumCertificate
	voted    = make(map[string]string)

	activeMu      sync.Mutex
	activeBlock   *UpperBlock
	activeStarted time.Time

	hotStuffHTTPClient = &http.Client{Timeout: 3 * time.Second}
)

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(getEnvDefault(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		log.Printf("[HotStuff][설정 경고] %s=%q 값이 올바르지 않아 기본값 %d을(를) 사용합니다.", key, value, fallback)
		return fallback
	}
	return parsed
}

func initializeHotStuff() {
	height, ok := getLatestHeight()
	if !ok || height < 0 {
		currentView.Store(0)
		return
	}
	view := uint64(height)
	if block, err := getBlockByIndex(height); err == nil && block.HotStuff != nil {
		view = block.HotStuff.View
		updateHighestQC(block.HotStuff.CommitQC)
		updateLockedQC(block.HotStuff.PreCommitQC)
	}
	currentView.Store(view)
	log.Printf("[HotStuff][초기화] 마지막 높이=%d, 마지막 뷰=%d", height, view)
}

func getOrCreateHotStuffState(view uint64, leader string, block UpperBlock, participants []string) *hotStuffViewState {
	hotStuffStatesMu.Lock()
	defer hotStuffStatesMu.Unlock()
	if state, ok := hotStuffStates[view]; ok {
		return state
	}
	state := &hotStuffViewState{
		View:         view,
		Leader:       leader,
		Block:        block,
		Participants: append([]string(nil), participants...),
		Collectors: map[HotStuffPhase]*voteCollector{
			PhasePrepare: newVoteCollector(), PhasePreCommit: newVoteCollector(), PhaseCommit: newVoteCollector(),
		},
		QCs:       make(map[HotStuffPhase]QuorumCertificate),
		StartedAt: time.Now(),
	}
	hotStuffStates[view] = state
	return state
}

func startConsensusWatcher() {
	ticker := time.NewTicker(time.Duration(ConsWatcherTime) * time.Second)
	defer ticker.Stop()
	var firstPendingAt time.Time

	log.Printf("[HotStuff][감시기] 시작: 배치=%d건, 배치 대기=%s, 뷰 타임아웃=%s",
		ConsensusBatchSize, ConsensusTimeout, ViewTimeout)
	for range ticker.C {
		if self != getBootAddr() {
			continue
		}
		if consensusInProgress.Load() {
			activeMu.Lock()
			timedOut := activeBlock != nil && time.Since(activeStarted) >= ViewTimeout
			var retry UpperBlock
			if timedOut {
				retry = *activeBlock
				activeStarted = time.Now()
			}
			activeMu.Unlock()
			if timedOut {
				log.Printf("[HotStuff][페이스메이커] 뷰 %d 타임아웃(%s). 같은 블록을 새 뷰에서 재제안합니다.", currentView.Load(), ViewTimeout)
				launchHotStuffView(retry, "뷰 타임아웃 재시도")
			}
			continue
		}

		pendingCount := getPendingCnt()
		if pendingCount == 0 {
			firstPendingAt = time.Time{}
			continue
		}
		if firstPendingAt.IsZero() {
			firstPendingAt = time.Now()
		}
		fullBatch := pendingCount >= ConsensusBatchSize
		batchTimedOut := time.Since(firstPendingAt) >= ConsensusTimeout
		if !fullBatch && !batchTimedOut {
			continue
		}
		entries := popPending()
		if len(entries) == 0 || !consensusInProgress.CompareAndSwap(false, true) {
			continue
		}
		block := createProposedBlock(entries)
		activeMu.Lock()
		activeBlock = &block
		activeStarted = time.Now()
		activeMu.Unlock()
		reason := "배치 대기시간 만료"
		if fullBatch {
			reason = "배치 크기 충족"
		}
		log.Printf("[HotStuff][합의 시작] 블록 #%d, 레코드=%d건, 사유=%s", block.Index, len(entries), reason)
		launchHotStuffView(block, reason)
		firstPendingAt = time.Time{}
	}
}

func launchHotStuffView(block UpperBlock, reason string) {
	view := currentView.Add(1)
	leader := self
	participants := consensusParticipants()
	justify := highestQCCopy()
	state := getOrCreateHotStuffState(view, leader, block, participants)
	state.StartedAt = time.Now()
	activeMu.Lock()
	activeBlock = &block
	activeStarted = time.Now()
	activeMu.Unlock()

	proposal := hotStuffProposal{View: view, Leader: leader, Block: block, Participants: participants, Justify: justify}
	justifyText := "없음(제네시스 직후)"
	if justify != nil {
		justifyText = fmt.Sprintf("뷰=%d/%s/%s", justify.View, justify.Phase, shortHash(justify.BlockHash))
	}
	log.Printf("[HotStuff][PROPOSE] 뷰=%d, 리더=%s, 블록=%s, 참여노드=%d, 정족수=%d, justifyQC=%s, 사유=%s",
		view, leader, shortHash(block.BlockHash), len(participants), quorumSizeFor(len(participants)), justifyText, reason)
	broadcastHotStuff("/hotstuff/propose", proposal, participants)
}

func handleHotStuffProposal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 요청만 허용됩니다", http.StatusMethodNotAllowed)
		return
	}
	var proposal hotStuffProposal
	if err := json.NewDecoder(r.Body).Decode(&proposal); err != nil {
		http.Error(w, "제안 JSON 형식이 올바르지 않습니다", http.StatusBadRequest)
		return
	}
	if err := validateProposal(proposal); err != nil {
		log.Printf("[HotStuff][PROPOSE 거부] 뷰=%d, 사유=%v", proposal.View, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	advanceCurrentView(proposal.View)
	state := getOrCreateHotStuffState(proposal.View, proposal.Leader, proposal.Block, proposal.Participants)
	state.mu.Lock()
	if state.Block.BlockHash != proposal.Block.BlockHash || state.Leader != proposal.Leader {
		state.mu.Unlock()
		http.Error(w, "같은 뷰에 상충하는 제안이 이미 존재합니다", http.StatusConflict)
		return
	}
	state.mu.Unlock()

	consensusInProgress.Store(true)
	activeMu.Lock()
	copyBlock := proposal.Block
	activeBlock = &copyBlock
	activeStarted = time.Now()
	activeMu.Unlock()
	log.Printf("[HotStuff][PREPARE] 뷰=%d 제안 검증 성공: 블록=%s, 이전해시=%s. Prepare 투표를 전송합니다.",
		proposal.View, shortHash(proposal.Block.BlockHash), shortHash(proposal.Block.PrevHash))
	if err := sendVote(proposal.View, PhasePrepare, proposal.Block.BlockHash, proposal.Leader); err != nil {
		log.Printf("[HotStuff][PREPARE 오류] 투표 전송 실패: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func validateProposal(proposal hotStuffProposal) error {
	if proposal.View == 0 || proposal.Leader == "" || proposal.Block.BlockHash == "" {
		return fmt.Errorf("필수 제안 필드가 비어 있습니다")
	}
	if proposal.Leader != getBootAddr() {
		return fmt.Errorf("현재 리더(%s)가 아닌 노드의 제안입니다: %s", getBootAddr(), proposal.Leader)
	}
	if !isSortedUnique(proposal.Participants) || !containsString(proposal.Participants, proposal.Leader) || !containsString(proposal.Participants, self) {
		return fmt.Errorf("참여자 스냅샷이 유효하지 않습니다")
	}
	if expected := consensusParticipants(); !sameStringList(proposal.Participants, expected) {
		return fmt.Errorf("확정된 Gov 검증자 집합과 제안 참여자가 다릅니다: 현재=%v 제안=%v", expected, proposal.Participants)
	}
	height, ok := getLatestHeight()
	if !ok || height < 0 {
		return fmt.Errorf("로컬 제네시스 블록이 없습니다")
	}
	prev, err := getBlockByIndex(height)
	if err != nil {
		return fmt.Errorf("이전 블록 조회 실패: %w", err)
	}
	if err := validateUpperBlock(proposal.Block, prev); err != nil {
		return fmt.Errorf("블록 구조 검증 실패: %w", err)
	}
	if proposal.Justify != nil {
		if err := verifyQuorumCertificate(*proposal.Justify); err != nil {
			return fmt.Errorf("justify QC 검증 실패: %w", err)
		}
	}
	if !safeToVote(proposal.Block, proposal.Justify) {
		return fmt.Errorf("잠금 QC 안전 규칙을 만족하지 않습니다")
	}
	return nil
}

func handleHotStuffVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 요청만 허용됩니다", http.StatusMethodNotAllowed)
		return
	}
	var vote hotStuffVote
	if err := json.NewDecoder(r.Body).Decode(&vote); err != nil {
		http.Error(w, "투표 JSON 형식이 올바르지 않습니다", http.StatusBadRequest)
		return
	}
	state := hotStuffState(vote.View)
	if state == nil {
		http.Error(w, "알 수 없는 뷰입니다", http.StatusNotFound)
		return
	}
	state.mu.Lock()
	if self != state.Leader || vote.BlockHash != state.Block.BlockHash || !containsString(state.Participants, vote.Voter) {
		state.mu.Unlock()
		http.Error(w, "투표 대상 또는 리더 정보가 일치하지 않습니다", http.StatusBadRequest)
		return
	}
	collector, phaseOK := state.Collectors[vote.Phase]
	if !phaseOK {
		state.mu.Unlock()
		http.Error(w, "지원하지 않는 투표 단계입니다", http.StatusBadRequest)
		return
	}
	if !verifyHotStuffVote(vote, state) {
		state.mu.Unlock()
		log.Printf("[HotStuff][투표 거부] 뷰=%d 단계=%s 서명자=%s: ECDSA 검증 실패", vote.View, vote.Phase, vote.Voter)
		http.Error(w, "투표 서명이 유효하지 않습니다", http.StatusForbidden)
		return
	}
	if !collector.add(vote.Voter, vote.Signature) {
		state.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	}
	count := len(collector.votes)
	required := quorumSizeFor(len(state.Participants))
	voterRole := "Gov 노드"
	if isHosRepresentativeEndpoint(vote.Voter) {
		voterRole = "Hos 리더 대표"
	}
	log.Printf("[HotStuff][%s 투표] 뷰=%d, 서명자=%s, 역할=%s, 수집=%d/%d", vote.Phase, vote.View, vote.Voter, voterRole, count, required)
	if count < required {
		state.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if _, alreadyBuilt := state.QCs[vote.Phase]; alreadyBuilt {
		state.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	}
	qc := buildQC(state, vote.Phase, collector.votes)
	state.QCs[vote.Phase] = qc
	certificates := certificateChain(state)
	block := state.Block
	participants := append([]string(nil), state.Participants...)
	state.mu.Unlock()

	log.Printf("[HotStuff][%s QC 형성] 뷰=%d, 블록=%s, 유효 서명=%d/%d. 다음 단계로 전파합니다.",
		vote.Phase, vote.View, shortHash(vote.BlockHash), len(qc.Signatures), required)
	envelope := hotStuffQCEnvelope{View: vote.View, Leader: self, Block: block, Certificates: certificates}
	broadcastHotStuff("/hotstuff/qc", envelope, participants)
	w.WriteHeader(http.StatusCreated)
}

func handleHotStuffQC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 요청만 허용됩니다", http.StatusMethodNotAllowed)
		return
	}
	var envelope hotStuffQCEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		http.Error(w, "QC JSON 형식이 올바르지 않습니다", http.StatusBadRequest)
		return
	}
	if len(envelope.Certificates) == 0 {
		http.Error(w, "QC 인증서 체인이 비어 있습니다", http.StatusBadRequest)
		return
	}
	state := hotStuffState(envelope.View)
	if state == nil {
		http.Error(w, "QC에 대응하는 제안을 찾을 수 없습니다", http.StatusNotFound)
		return
	}
	state.mu.Lock()
	if envelope.Leader != state.Leader || envelope.Block.BlockHash != state.Block.BlockHash {
		state.mu.Unlock()
		http.Error(w, "QC의 리더 또는 블록이 제안과 다릅니다", http.StatusBadRequest)
		return
	}
	for _, qc := range envelope.Certificates {
		if qc.View != envelope.View || qc.BlockHash != state.Block.BlockHash {
			state.mu.Unlock()
			http.Error(w, "QC 뷰 또는 블록 해시가 일치하지 않습니다", http.StatusBadRequest)
			return
		}
		if err := verifyQuorumCertificate(qc); err != nil {
			state.mu.Unlock()
			log.Printf("[HotStuff][QC 거부] 뷰=%d 단계=%s: %v", qc.View, qc.Phase, err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		state.QCs[qc.Phase] = qc
		updateHighestQC(qc)
	}
	lastQC := envelope.Certificates[len(envelope.Certificates)-1]
	if lastQC.Phase == PhasePreCommit {
		updateLockedQC(lastQC)
	}
	if lastQC.Phase == PhaseCommit {
		if state.Finalized {
			state.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		prepareQC, prepareOK := state.QCs[PhasePrepare]
		preCommitQC, preCommitOK := state.QCs[PhasePreCommit]
		commitQC, commitOK := state.QCs[PhaseCommit]
		if !prepareOK || !preCommitOK || !commitOK {
			state.mu.Unlock()
			http.Error(w, "3단계 QC 체인이 완성되지 않았습니다", http.StatusConflict)
			return
		}
		state.Finalized = true
		finalBlock := state.Block
		finalBlock.Elapsed = float32(time.Since(state.StartedAt).Seconds())
		finalBlock.HotStuff = &HotStuffProof{View: lastQC.View, PrepareQC: prepareQC, PreCommitQC: preCommitQC, CommitQC: commitQC}
		finalBlock.Signatures = legacySignatures(commitQC)
		state.mu.Unlock()

		log.Printf("[HotStuff][DECIDE] 뷰=%d의 Commit QC 검증 완료. 블록 #%d을(를) 최종 확정합니다. (해시=%s, 지연=%.4f초)",
			lastQC.View, finalBlock.Index, shortHash(finalBlock.BlockHash), finalBlock.Elapsed)
		if err := onBlockReceived(finalBlock); err != nil {
			log.Printf("[HotStuff][DECIDE 오류] 확정 블록 저장 실패: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		return
	}
	state.mu.Unlock()

	nextPhase := PhasePreCommit
	if lastQC.Phase == PhasePreCommit {
		nextPhase = PhaseCommit
	}
	log.Printf("[HotStuff][%s] 뷰=%d의 %s QC 검증 성공. %s 투표를 전송합니다.", nextPhase, lastQC.View, lastQC.Phase, nextPhase)
	if err := sendVote(lastQC.View, nextPhase, lastQC.BlockHash, envelope.Leader); err != nil {
		log.Printf("[HotStuff][%s 오류] 투표 전송 실패: %v", nextPhase, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func sendVote(view uint64, phase HotStuffPhase, blockHash, leader string) error {
	if !recordVote(view, phase, blockHash) {
		return nil
	}
	privateKey, ok := getMeta("meta_gov_privkey")
	if !ok {
		return fmt.Errorf("노드 개인키가 없습니다")
	}
	state := hotStuffState(view)
	if state == nil {
		return fmt.Errorf("투표할 뷰 상태를 찾을 수 없습니다: %d", view)
	}
	state.mu.Lock()
	leaderFromState := state.Leader
	participants := append([]string(nil), state.Participants...)
	state.mu.Unlock()
	if leader != leaderFromState {
		return fmt.Errorf("투표 대상 리더가 뷰 상태와 다릅니다")
	}
	digest := hotStuffVoteDigest(view, phase, blockHash, leader, participants)
	signature := makeAnchorSignature(privateKey, hex.EncodeToString(digest), "")
	if signature == "" {
		return fmt.Errorf("ECDSA 투표 서명 생성에 실패했습니다")
	}
	vote := hotStuffVote{View: view, Phase: phase, BlockHash: blockHash, Voter: self, Signature: signature}
	go func() {
		if err := postHotStuff(leader, "/hotstuff/vote", vote); err != nil {
			log.Printf("[HotStuff][네트워크 오류] %s 리더에게 %s 투표를 보내지 못했습니다: %v", leader, phase, err)
		}
	}()
	return nil
}

func buildQC(state *hotStuffViewState, phase HotStuffPhase, votes map[string]string) QuorumCertificate {
	signers := make([]string, 0, len(votes))
	for signer := range votes {
		signers = append(signers, signer)
	}
	sort.Strings(signers)
	signatures := make([]HotStuffSignature, 0, len(signers))
	for _, signer := range signers {
		signatures = append(signatures, HotStuffSignature{Voter: signer, Signature: votes[signer]})
	}
	return QuorumCertificate{
		View: state.View, Phase: phase, BlockHash: state.Block.BlockHash, Leader: state.Leader,
		Participants: append([]string(nil), state.Participants...), Signatures: signatures,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func verifyQuorumCertificate(qc QuorumCertificate) error {
	if qc.View == 0 || qc.BlockHash == "" || qc.Leader == "" {
		return fmt.Errorf("QC 필수 필드가 비어 있습니다")
	}
	if qc.Phase != PhasePrepare && qc.Phase != PhasePreCommit && qc.Phase != PhaseCommit {
		return fmt.Errorf("알 수 없는 QC 단계: %s", qc.Phase)
	}
	if !isSortedUnique(qc.Participants) || !containsString(qc.Participants, qc.Leader) {
		return fmt.Errorf("QC 참여자 스냅샷이 유효하지 않습니다")
	}
	required := quorumSizeFor(len(qc.Participants))
	if len(qc.Signatures) < required {
		return fmt.Errorf("QC 서명 부족: %d/%d", len(qc.Signatures), required)
	}
	digest := hotStuffVoteDigest(qc.View, qc.Phase, qc.BlockHash, qc.Leader, qc.Participants)
	seen := make(map[string]bool, len(qc.Signatures))
	valid := 0
	for _, signed := range qc.Signatures {
		if seen[signed.Voter] || !containsString(qc.Participants, signed.Voter) {
			return fmt.Errorf("중복되었거나 참여자가 아닌 서명자: %s", signed.Voter)
		}
		seen[signed.Voter] = true
		publicKey, ok := publicKeyFor(signed.Voter)
		if !ok || !verifyECDSA(publicKey, digest, signed.Signature) {
			return fmt.Errorf("서명자 %s의 ECDSA 서명이 유효하지 않습니다", signed.Voter)
		}
		valid++
	}
	if valid < required {
		return fmt.Errorf("유효 QC 서명 부족: %d/%d", valid, required)
	}
	return nil
}

func verifyHotStuffVote(vote hotStuffVote, state *hotStuffViewState) bool {
	publicKey, ok := publicKeyFor(vote.Voter)
	return ok && verifyECDSA(publicKey,
		hotStuffVoteDigest(vote.View, vote.Phase, vote.BlockHash, state.Leader, state.Participants), vote.Signature)
}

func hotStuffVoteDigest(view uint64, phase HotStuffPhase, blockHash, leader string, participants []string) []byte {
	chainID := ""
	if ch != nil {
		chainID = ch.govID
	}
	membership := sha256.Sum256([]byte(strings.Join(participants, "\x00")))
	payload := fmt.Sprintf("HOTSTUFF|v1|%s|%d|%s|%s|%s|%x", chainID, view, phase, blockHash, leader, membership)
	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

func publicKeyFor(address string) (string, bool) {
	if address == self {
		return getMeta("meta_gov_pubkey")
	}
	pkMu.RLock()
	key, ok := peerPubKeys[address]
	pkMu.RUnlock()
	if ok && key != "" {
		return key, true
	}
	return representativePublicKey(address)
}

func safeToVote(block UpperBlock, justify *QuorumCertificate) bool {
	safetyMu.Lock()
	defer safetyMu.Unlock()
	if lockedQC == nil {
		return true
	}
	if block.BlockHash == lockedQC.BlockHash || block.PrevHash == lockedQC.BlockHash {
		return true
	}
	return justify != nil && justify.View > lockedQC.View && justify.BlockHash == block.BlockHash
}

func updateHighestQC(qc QuorumCertificate) {
	safetyMu.Lock()
	defer safetyMu.Unlock()
	if highQC == nil || qc.View > highQC.View || (qc.View == highQC.View && phaseRank(qc.Phase) > phaseRank(highQC.Phase)) {
		copyQC := qc
		highQC = &copyQC
	}
}

func updateLockedQC(qc QuorumCertificate) {
	safetyMu.Lock()
	defer safetyMu.Unlock()
	if lockedQC == nil || qc.View >= lockedQC.View {
		copyQC := qc
		lockedQC = &copyQC
		log.Printf("[HotStuff][LOCK] 뷰=%d, 블록=%s의 Pre-Commit QC에 잠금 상태를 갱신했습니다.", qc.View, shortHash(qc.BlockHash))
	}
}

func highestQCCopy() *QuorumCertificate {
	safetyMu.Lock()
	defer safetyMu.Unlock()
	if highQC == nil {
		return nil
	}
	copyQC := *highQC
	copyQC.Participants = append([]string(nil), highQC.Participants...)
	copyQC.Signatures = append([]HotStuffSignature(nil), highQC.Signatures...)
	return &copyQC
}

func finishHotStuffConsensus(block UpperBlock) {
	consensusInProgress.Store(false)
	activeMu.Lock()
	activeBlock = nil
	activeStarted = time.Time{}
	activeMu.Unlock()
	if block.HotStuff != nil {
		updateHighestQC(block.HotStuff.CommitQC)
		updateLockedQC(block.HotStuff.PreCommitQC)
	}
	hotStuffStatesMu.Lock()
	for view := range hotStuffStates {
		if block.HotStuff != nil && view+2 < block.HotStuff.View {
			delete(hotStuffStates, view)
		}
	}
	hotStuffStatesMu.Unlock()
}

func consensusParticipants() []string {
	set := map[string]struct{}{self: {}}
	for _, peer := range peersSnapshot() {
		if peer != "" {
			set[peer] = struct{}{}
		}
	}
	for _, endpoint := range representativeEndpoints() {
		if endpoint != "" {
			set[endpoint] = struct{}{}
		}
	}
	participants := make([]string, 0, len(set))
	for node := range set {
		participants = append(participants, node)
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

func quorumSizeFor(n int) int {
	if n <= 0 {
		return 0
	}
	f := (n - 1) / 3
	return n - f
}

func certificateChain(state *hotStuffViewState) []QuorumCertificate {
	chain := make([]QuorumCertificate, 0, 3)
	for _, phase := range []HotStuffPhase{PhasePrepare, PhasePreCommit, PhaseCommit} {
		if qc, ok := state.QCs[phase]; ok {
			chain = append(chain, qc)
		}
	}
	return chain
}

func legacySignatures(qc QuorumCertificate) []string {
	out := make([]string, 0, len(qc.Signatures))
	for _, signed := range qc.Signatures {
		out = append(out, signed.Signature)
	}
	return out
}

func phaseRank(phase HotStuffPhase) int {
	switch phase {
	case PhasePrepare:
		return 1
	case PhasePreCommit:
		return 2
	case PhaseCommit:
		return 3
	default:
		return 0
	}
}

func recordVote(view uint64, phase HotStuffPhase, blockHash string) bool {
	safetyMu.Lock()
	defer safetyMu.Unlock()
	key := fmt.Sprintf("%d|%s", view, phase)
	if previous, exists := voted[key]; exists {
		return previous == blockHash
	}
	voted[key] = blockHash
	return true
}

func hotStuffState(view uint64) *hotStuffViewState {
	hotStuffStatesMu.Lock()
	defer hotStuffStatesMu.Unlock()
	return hotStuffStates[view]
}

func advanceCurrentView(view uint64) {
	for {
		old := currentView.Load()
		if view <= old || currentView.CompareAndSwap(old, view) {
			return
		}
	}
}

func broadcastHotStuff(path string, payload any, participants []string) {
	for _, node := range participants {
		node := node
		go func() {
			if err := postHotStuff(node, path, payload); err != nil {
				log.Printf("[HotStuff][네트워크 경고] %s%s 전송 실패: %v", node, path, err)
			}
		}()
	}
}

func postHotStuff(node, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := hotStuffHTTPClient.Post("http://"+node+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP 상태 %d", resp.StatusCode)
	}
	return nil
}

func containsString(items []string, target string) bool {
	index := sort.SearchStrings(items, target)
	return index < len(items) && items[index] == target
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

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

func hotStuffStatus() map[string]any {
	safetyMu.Lock()
	defer safetyMu.Unlock()
	status := map[string]any{
		"engine": "Basic HotStuff", "view": currentView.Load(),
		"in_progress": consensusInProgress.Load(), "leader": getBootAddr(),
	}
	if highQC != nil {
		status["high_qc"] = map[string]any{"view": highQC.View, "phase": highQC.Phase, "block_hash": highQC.BlockHash}
	}
	if lockedQC != nil {
		status["locked_qc"] = map[string]any{"view": lockedQC.View, "phase": lockedQC.Phase, "block_hash": lockedQC.BlockHash}
	}
	return status
}
