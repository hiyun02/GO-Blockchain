package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type GovHotStuffPhase string

const (
	GovPhasePrepare   GovHotStuffPhase = "PREPARE"
	GovPhasePreCommit GovHotStuffPhase = "PRE_COMMIT"
	GovPhaseCommit    GovHotStuffPhase = "COMMIT"
)

type GovHotStuffSignature struct {
	Voter     string `json:"voter"`
	Signature string `json:"signature"`
}

type GovQuorumCertificate struct {
	View         uint64                 `json:"view"`
	Phase        GovHotStuffPhase       `json:"phase"`
	BlockHash    string                 `json:"block_hash"`
	Leader       string                 `json:"leader"`
	Participants []string               `json:"participants"`
	Signatures   []GovHotStuffSignature `json:"signatures"`
	CreatedAt    string                 `json:"created_at"`
}

type GovHotStuffProof struct {
	View        uint64               `json:"view"`
	PrepareQC   GovQuorumCertificate `json:"prepare_qc"`
	PreCommitQC GovQuorumCertificate `json:"pre_commit_qc"`
	CommitQC    GovQuorumCertificate `json:"commit_qc"`
}

type GovRepresentative struct {
	HosID            string `json:"hos_id"`
	LeaderAddr       string `json:"leader_addr"`
	Endpoint         string `json:"gov_endpoint"`
	PublicKey        string `json:"gov_public_key"`
	LeadershipTerm   uint64 `json:"leadership_term"`
	LowerHeight      int    `json:"lower_height"`
	LowerBlockHash   string `json:"lower_block_hash"`
	ActivationHeight int    `json:"activation_height"`
	RegisteredAt     string `json:"registered_at"`
}

type GovRepresentativeChange struct {
	Action                 string            `json:"action"`
	Representative         GovRepresentative `json:"representative"`
	HosLeaderPublicKey     string            `json:"hos_leader_public_key"`
	AuthorizationSignature string            `json:"authorization_signature"`
}

type GovAnchorSubmission struct {
	HosID          string `json:"hos_id"`
	HosBoot        string `json:"hos_boot"`
	Root           string `json:"root"`
	Ts             string `json:"ts"`
	Sig            string `json:"sig"`
	LowerHeight    int    `json:"lower_height"`
	LowerBlockHash string `json:"lower_block_hash"`
	GovEndpoint    string `json:"gov_endpoint"`
	GovPublicKey   string `json:"gov_public_key"`
	LeadershipTerm uint64 `json:"leadership_term"`
}

type govHotStuffProposal struct {
	View         uint64                `json:"view"`
	Leader       string                `json:"leader"`
	Block        UpperBlock            `json:"block"`
	Participants []string              `json:"participants"`
	Justify      *GovQuorumCertificate `json:"justify_qc,omitempty"`
}

type govHotStuffVote struct {
	View      uint64           `json:"view"`
	Phase     GovHotStuffPhase `json:"phase"`
	BlockHash string           `json:"block_hash"`
	Voter     string           `json:"voter"`
	Signature string           `json:"signature"`
}

type govHotStuffQCEnvelope struct {
	View         uint64                 `json:"view"`
	Leader       string                 `json:"leader"`
	Block        UpperBlock             `json:"block"`
	Certificates []GovQuorumCertificate `json:"certificates"`
}

func govAnchorSubmissionDigest(req GovAnchorSubmission) []byte {
	payload := fmt.Sprintf("HOS-ANCHOR|v2|%s|%s|%d|%s|%s|%s|%s|%d|%s",
		req.HosID, req.HosBoot, req.LowerHeight, req.LowerBlockHash, req.Root,
		req.GovEndpoint, req.GovPublicKey, req.LeadershipTerm, req.Ts)
	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

func govVoteDigest(govID string, view uint64, phase GovHotStuffPhase, blockHash, leader string, participants []string) []byte {
	membership := sha256.Sum256([]byte(strings.Join(participants, "\x00")))
	payload := fmt.Sprintf("HOTSTUFF|v1|%s|%d|%s|%s|%s|%x", govID, view, phase, blockHash, leader, membership)
	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

func computeGovRepresentativeChangesHash(records []AnchorRecord) string {
	changes := make([]GovRepresentativeChange, 0)
	for _, record := range records {
		if record.Representative != nil {
			changes = append(changes, *record.Representative)
		}
	}
	if len(changes) == 0 {
		return ""
	}
	data, _ := json.Marshal(changes)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func computeGovUpperBlockHash(block UpperBlock) string {
	header := struct {
		Index             int    `json:"index"`
		GovID             string `json:"gov_id"`
		PrevHash          string `json:"prev_hash"`
		Timestamp         string `json:"timestamp"`
		MerkleRoot        string `json:"merkle_root"`
		ConfigurationHash string `json:"configuration_hash,omitempty"`
		Proposer          string `json:"proposer"`
	}{block.Index, block.GovID, block.PrevHash, block.Timestamp, block.MerkleRoot, block.ConfigurationHash, block.Proposer}
	return sha256Hex(jsonCanonical(header))
}

func validateGovUpperBlock(block, previous UpperBlock) error {
	if block.Index != previous.Index+1 || block.PrevHash != previous.BlockHash || block.GovID != previous.GovID {
		return fmt.Errorf("Gov 블록 연결 정보가 일치하지 않습니다")
	}
	leaves := make([]string, len(block.Records))
	for i, record := range block.Records {
		leaves[i] = record.LowerRoot
	}
	expectedRoot := ""
	if len(leaves) > 0 {
		expectedRoot = merkleRootHex(leaves)
	}
	if block.MerkleRoot != expectedRoot || block.ConfigurationHash != computeGovRepresentativeChangesHash(block.Records) {
		return fmt.Errorf("Gov 블록 MerkleRoot 또는 대표 변경 해시가 일치하지 않습니다")
	}
	if block.BlockHash != computeGovUpperBlockHash(block) {
		return fmt.Errorf("Gov 블록 해시가 일치하지 않습니다")
	}
	state, err := govRepresentativeStateAt(previous.Index)
	if err != nil {
		return fmt.Errorf("기존 Gov 대표 상태 복원 실패: %w", err)
	}
	if err := validateGovRepresentativeChanges(block.Records, state); err != nil {
		return fmt.Errorf("Gov 대표 변경 검증 실패: %w", err)
	}
	return nil
}

func govRepresentativeStateAt(height int) (map[string]GovRepresentative, error) {
	state := make(map[string]GovRepresentative)
	for index := 1; index <= height; index++ {
		block, err := loadGovRepresentativeBlock(index)
		if err != nil {
			return nil, err
		}
		for _, record := range block.Records {
			if record.Representative != nil {
				state[record.Representative.Representative.HosID] = record.Representative.Representative
			}
		}
	}
	return state, nil
}

func validateGovRepresentativeChanges(records []AnchorRecord, state map[string]GovRepresentative) error {
	for _, record := range records {
		if record.Representative == nil {
			continue
		}
		change := *record.Representative
		rep := change.Representative
		if rep.HosID == "" || record.HosID != rep.HosID || rep.LeaderAddr == "" || rep.Endpoint == "" || rep.PublicKey == "" || rep.LowerHeight <= 0 {
			return fmt.Errorf("Hos 대표 필수 정보가 비어 있거나 앵커 Hos ID와 다릅니다")
		}
		if rep.Endpoint != strings.TrimRight(rep.LeaderAddr, "/")+"/gov" {
			return fmt.Errorf("Hos %s의 Gov 대표 엔드포인트가 리더 주소와 일치하지 않습니다", rep.HosID)
		}
		expectedAction := "ADD"
		if current, exists := state[rep.HosID]; exists {
			if rep.LowerHeight <= current.LowerHeight || rep.LeadershipTerm < current.LeadershipTerm {
				return fmt.Errorf("Hos %s의 대표 변경이 과거 상태를 되돌립니다", rep.HosID)
			}
			expectedAction = "REFRESH"
			if current.Endpoint != rep.Endpoint || current.PublicKey != rep.PublicKey || current.LeaderAddr != rep.LeaderAddr {
				expectedAction = "REPLACE"
			}
		}
		if change.Action != expectedAction {
			return fmt.Errorf("Hos %s 대표 변경 유형 불일치: 요청=%s 예상=%s", rep.HosID, change.Action, expectedAction)
		}
		req := GovAnchorSubmission{
			HosID: rep.HosID, HosBoot: rep.LeaderAddr, Root: record.LowerRoot,
			Ts: record.AnchorTimestamp, Sig: change.AuthorizationSignature,
			LowerHeight: rep.LowerHeight, LowerBlockHash: rep.LowerBlockHash,
			GovEndpoint: rep.Endpoint, GovPublicKey: rep.PublicKey, LeadershipTerm: rep.LeadershipTerm,
		}
		if !verifyECDSA(change.HosLeaderPublicKey, govAnchorSubmissionDigest(req), change.AuthorizationSignature) {
			return fmt.Errorf("Hos %s 대표 위임 서명이 유효하지 않습니다", rep.HosID)
		}
		state[rep.HosID] = rep
	}
	return nil
}

type govRepresentativeView struct {
	mu           sync.Mutex
	Proposal     govHotStuffProposal
	Certificates map[GovHotStuffPhase]GovQuorumCertificate
	Finalized    bool
}

type govRepresentativeRuntime struct {
	mu           sync.RWMutex
	GovID        string
	Leader       string
	Participants []string
	PublicKeys   map[string]string
	Views        map[uint64]*govRepresentativeView
	Voted        map[string]string
	LockedQC     *GovQuorumCertificate
	LastSync     time.Time
}

var govRepRuntime = govRepresentativeRuntime{
	PublicKeys: make(map[string]string), Views: make(map[uint64]*govRepresentativeView), Voted: make(map[string]string),
}

var govRepresentativeHTTPClient = &http.Client{Timeout: 4 * time.Second}

func ensureGovRepresentativeKeyPair() {
	if _, ok := getMeta("meta_gov_rep_privkey"); ok {
		return
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("[Gov 대표][초기화 오류] 대표키 생성 실패: %v", err)
	}
	privateDER, _ := x509.MarshalECPrivateKey(privateKey)
	publicDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	_ = putMeta("meta_gov_rep_privkey", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})))
	_ = putMeta("meta_gov_rep_pubkey", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})))
	log.Printf("[Gov 대표][초기화] Hos=%s의 Gov 합의 전용 키를 준비했습니다.", selfID())
}

func govRepresentativeEndpoint() string {
	return strings.TrimRight(self, "/") + "/gov"
}

func isCurrentHosLeader() bool {
	return self != "" && self == getBootAddr()
}

func govRepresentativeActive() bool {
	if !isCurrentHosLeader() {
		return false
	}
	govRepRuntime.mu.RLock()
	defer govRepRuntime.mu.RUnlock()
	return containsString(govRepRuntime.Participants, govRepresentativeEndpoint())
}

func refreshGovValidatorSet(leader string) error {
	resp, err := govRepresentativeHTTPClient.Get("http://" + leader + "/consensus/validators")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("검증자 조회 HTTP %d: %s", resp.StatusCode, string(body))
	}
	var snapshot struct {
		GovID        string            `json:"gov_id"`
		Leader       string            `json:"leader"`
		Participants []string          `json:"participants"`
		PublicKeys   map[string]string `json:"public_keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		return err
	}
	if snapshot.GovID == "" || snapshot.Leader != leader || !isSortedUnique(snapshot.Participants) {
		return fmt.Errorf("Gov 검증자 스냅샷이 유효하지 않습니다")
	}
	govRepRuntime.mu.Lock()
	govRepRuntime.GovID = snapshot.GovID
	govRepRuntime.Leader = snapshot.Leader
	govRepRuntime.Participants = append([]string(nil), snapshot.Participants...)
	govRepRuntime.PublicKeys = copyStringMap(snapshot.PublicKeys)
	govRepRuntime.LastSync = time.Now()
	govRepRuntime.mu.Unlock()
	return nil
}

func verifyGovQC(qc GovQuorumCertificate, govID string, keys map[string]string) error {
	if qc.View == 0 || qc.BlockHash == "" || qc.Leader == "" || !isSortedUnique(qc.Participants) {
		return fmt.Errorf("Gov QC 필수 정보가 올바르지 않습니다")
	}
	required := quorumSizeFor(len(qc.Participants))
	if len(qc.Signatures) < required {
		return fmt.Errorf("Gov QC 서명 부족: %d/%d", len(qc.Signatures), required)
	}
	digest := govVoteDigest(govID, qc.View, qc.Phase, qc.BlockHash, qc.Leader, qc.Participants)
	seen := make(map[string]bool)
	for _, signed := range qc.Signatures {
		if seen[signed.Voter] || !containsString(qc.Participants, signed.Voter) {
			return fmt.Errorf("Gov QC 중복/비참여 서명자: %s", signed.Voter)
		}
		seen[signed.Voter] = true
		if !verifyECDSA(keys[signed.Voter], digest, signed.Signature) {
			return fmt.Errorf("Gov QC 서명 검증 실패: %s", signed.Voter)
		}
	}
	return nil
}

func recordGovRepresentativeVote(view uint64, phase GovHotStuffPhase, blockHash string) bool {
	govRepRuntime.mu.Lock()
	defer govRepRuntime.mu.Unlock()
	key := fmt.Sprintf("%d|%s", view, phase)
	if previous, exists := govRepRuntime.Voted[key]; exists {
		return previous == blockHash
	}
	govRepRuntime.Voted[key] = blockHash
	return true
}

func sendGovRepresentativeVote(proposal govHotStuffProposal, phase GovHotStuffPhase) error {
	if !recordGovRepresentativeVote(proposal.View, phase, proposal.Block.BlockHash) {
		return fmt.Errorf("동일 뷰와 단계에서 다른 Gov 블록에 이미 투표했습니다")
	}
	privateKey, ok := getMeta("meta_gov_rep_privkey")
	if !ok {
		return fmt.Errorf("Gov 대표 개인키가 없습니다")
	}
	digest := govVoteDigest(proposal.Block.GovID, proposal.View, phase, proposal.Block.BlockHash, proposal.Leader, proposal.Participants)
	signature := makeAnchorSignature(privateKey, hex.EncodeToString(digest), "")
	vote := govHotStuffVote{View: proposal.View, Phase: phase, BlockHash: proposal.Block.BlockHash, Voter: govRepresentativeEndpoint(), Signature: signature}
	body, _ := json.Marshal(vote)
	resp, err := govRepresentativeHTTPClient.Post("http://"+proposal.Leader+"/hotstuff/vote", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Gov 리더가 투표를 거부했습니다: HTTP %d %s", resp.StatusCode, string(body))
	}
	log.Printf("[Gov 대표][%s 투표 전송] Hos=%s, 뷰=%d, 블록=%s, 대표=%s",
		phase, selfID(), proposal.View, shortHash(proposal.Block.BlockHash), govRepresentativeEndpoint())
	return nil
}

func handleGovHotStuffProposal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 요청만 허용됩니다", http.StatusMethodNotAllowed)
		return
	}
	if !isCurrentHosLeader() {
		log.Printf("[Gov 대표][제안 거부] 현재 Hos 리더가 아닙니다. 현재리더=%s, 수신노드=%s", getBootAddr(), self)
		http.Error(w, "현재 Hos 리더만 Gov 합의에 참여할 수 있습니다", http.StatusForbidden)
		return
	}
	var proposal govHotStuffProposal
	if err := json.NewDecoder(r.Body).Decode(&proposal); err != nil {
		http.Error(w, "Gov 제안 JSON 형식이 올바르지 않습니다", http.StatusBadRequest)
		return
	}
	if !containsString(proposal.Participants, govRepresentativeEndpoint()) {
		http.Error(w, "현재 Hos 리더가 Gov 검증자 집합에 없습니다", http.StatusForbidden)
		return
	}
	if err := refreshGovValidatorSet(proposal.Leader); err != nil {
		http.Error(w, "Gov 검증자 집합 조회 실패: "+err.Error(), http.StatusBadGateway)
		return
	}
	govRepRuntime.mu.RLock()
	participants := append([]string(nil), govRepRuntime.Participants...)
	keys := copyStringMap(govRepRuntime.PublicKeys)
	govID := govRepRuntime.GovID
	govRepRuntime.mu.RUnlock()
	if proposal.Block.GovID != govID || !sameOrderedStrings(proposal.Participants, participants) {
		http.Error(w, "Gov 체인 또는 검증자 집합이 일치하지 않습니다", http.StatusConflict)
		return
	}
	if err := syncGovRepresentativeChain(proposal.Leader); err != nil {
		http.Error(w, "Gov 장부 동기화 실패: "+err.Error(), http.StatusBadGateway)
		return
	}
	previous, err := loadGovRepresentativeBlock(proposal.Block.Index - 1)
	if err != nil {
		http.Error(w, "직전 Gov 블록을 찾을 수 없습니다", http.StatusConflict)
		return
	}
	if err := validateGovUpperBlock(proposal.Block, previous); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if proposal.Justify != nil {
		if err := verifyGovQC(*proposal.Justify, govID, keys); err != nil {
			http.Error(w, "Gov justify QC 검증 실패: "+err.Error(), http.StatusForbidden)
			return
		}
	}
	govRepRuntime.mu.Lock()
	govRepRuntime.Views[proposal.View] = &govRepresentativeView{Proposal: proposal, Certificates: make(map[GovHotStuffPhase]GovQuorumCertificate)}
	govRepRuntime.mu.Unlock()
	log.Printf("[Gov 대표][PROPOSE 검증] Hos=%s, 뷰=%d, Gov블록=%d, 참여자=%d, 정족수=%d",
		selfID(), proposal.View, proposal.Block.Index, len(proposal.Participants), quorumSizeFor(len(proposal.Participants)))
	if err := sendGovRepresentativeVote(proposal, GovPhasePrepare); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func copyStringMap(source map[string]string) map[string]string {
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func sameOrderedStrings(left, right []string) bool {
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

func saveGovRepresentativeBlock(block UpperBlock) error {
	data, err := json.Marshal(block)
	if err != nil {
		return err
	}
	if err := db.Put([]byte(fmt.Sprintf("gov_rep_block_%d", block.Index)), data, nil); err != nil {
		return err
	}
	return putMeta("gov_rep_height", fmt.Sprintf("%d", block.Index))
}

func loadGovRepresentativeBlock(index int) (UpperBlock, error) {
	data, err := db.Get([]byte(fmt.Sprintf("gov_rep_block_%d", index)), nil)
	if err != nil {
		return UpperBlock{}, err
	}
	var block UpperBlock
	if err := json.Unmarshal(data, &block); err != nil {
		return UpperBlock{}, err
	}
	return block, nil
}

func getGovRepresentativeHeight() (int, bool) {
	value, ok := getMeta("gov_rep_height")
	if !ok {
		return -1, false
	}
	var height int
	if _, err := fmt.Sscanf(value, "%d", &height); err != nil {
		return -1, false
	}
	return height, true
}

func handleGovHotStuffQC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 요청만 허용됩니다", http.StatusMethodNotAllowed)
		return
	}
	if !isCurrentHosLeader() {
		http.Error(w, "현재 Hos 리더만 Gov 합의에 참여할 수 있습니다", http.StatusForbidden)
		return
	}
	var envelope govHotStuffQCEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil || len(envelope.Certificates) == 0 {
		http.Error(w, "Gov QC JSON 형식이 올바르지 않습니다", http.StatusBadRequest)
		return
	}
	govRepRuntime.mu.RLock()
	viewState := govRepRuntime.Views[envelope.View]
	keys := copyStringMap(govRepRuntime.PublicKeys)
	govID := govRepRuntime.GovID
	govRepRuntime.mu.RUnlock()
	if viewState == nil {
		http.Error(w, "Gov QC에 대응하는 제안이 없습니다", http.StatusNotFound)
		return
	}
	viewState.mu.Lock()
	proposal := viewState.Proposal
	if envelope.Leader != proposal.Leader || envelope.Block.BlockHash != proposal.Block.BlockHash {
		viewState.mu.Unlock()
		http.Error(w, "Gov QC의 리더 또는 블록이 제안과 다릅니다", http.StatusBadRequest)
		return
	}
	for _, qc := range envelope.Certificates {
		if qc.View != envelope.View || qc.BlockHash != proposal.Block.BlockHash {
			viewState.mu.Unlock()
			http.Error(w, "Gov QC 뷰/블록 해시가 다릅니다", http.StatusBadRequest)
			return
		}
		if err := verifyGovQC(qc, govID, keys); err != nil {
			viewState.mu.Unlock()
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		viewState.Certificates[qc.Phase] = qc
	}
	lastQC := envelope.Certificates[len(envelope.Certificates)-1]
	if lastQC.Phase == GovPhasePreCommit {
		copyQC := lastQC
		govRepRuntime.mu.Lock()
		govRepRuntime.LockedQC = &copyQC
		govRepRuntime.mu.Unlock()
		log.Printf("[Gov 대표][LOCK] Hos=%s, 뷰=%d, Gov블록=%s", selfID(), lastQC.View, shortHash(lastQC.BlockHash))
	}
	if lastQC.Phase == GovPhaseCommit {
		if viewState.Finalized {
			viewState.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		prepare, ok1 := viewState.Certificates[GovPhasePrepare]
		preCommit, ok2 := viewState.Certificates[GovPhasePreCommit]
		commit, ok3 := viewState.Certificates[GovPhaseCommit]
		if !ok1 || !ok2 || !ok3 {
			viewState.mu.Unlock()
			http.Error(w, "Gov 3단계 QC가 완성되지 않았습니다", http.StatusConflict)
			return
		}
		viewState.Finalized = true
		block := proposal.Block
		block.HotStuff = &GovHotStuffProof{View: lastQC.View, PrepareQC: prepare, PreCommitQC: preCommit, CommitQC: commit}
		viewState.mu.Unlock()
		if err := saveGovRepresentativeBlock(block); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("[Gov 대표][DECIDE] Hos=%s가 Gov 블록 #%d을 확정했습니다. 뷰=%d, Commit서명=%d, 해시=%s",
			selfID(), block.Index, lastQC.View, len(commit.Signatures), shortHash(block.BlockHash))
		w.WriteHeader(http.StatusCreated)
		return
	}
	viewState.mu.Unlock()

	next := GovPhasePreCommit
	if lastQC.Phase == GovPhasePreCommit {
		next = GovPhaseCommit
	}
	if err := sendGovRepresentativeVote(proposal, next); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func handleGovHotStuffVote(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Hos 대표는 현재 Gov 제안 리더가 아니므로 투표를 수집하지 않습니다", http.StatusMethodNotAllowed)
}

func handleGovRepresentativeStatus(w http.ResponseWriter, r *http.Request) {
	govRepRuntime.mu.RLock()
	participants := append([]string(nil), govRepRuntime.Participants...)
	govID := govRepRuntime.GovID
	leader := govRepRuntime.Leader
	lastSync := govRepRuntime.LastSync
	govRepRuntime.mu.RUnlock()
	height, _ := getGovRepresentativeHeight()
	writeJSON(w, http.StatusOK, map[string]any{
		"hos_id": selfID(), "leader_node": isCurrentHosLeader(), "active": govRepresentativeActive(),
		"endpoint": govRepresentativeEndpoint(), "gov_id": govID, "gov_leader": leader,
		"gov_height": height, "participants": participants, "last_sync": lastSync.Format(time.RFC3339Nano),
	})
}

func syncGovRepresentativeChain(leader string) error {
	resp, err := govRepresentativeHTTPClient.Get("http://" + leader + "/blocks?offset=0&limit=1000000")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Gov 블록 조회 HTTP %d", resp.StatusCode)
	}
	var page struct {
		Items []UpperBlock `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return err
	}
	localHeight, ok := getGovRepresentativeHeight()
	if !ok {
		localHeight = -1
	}
	added := 0
	for _, block := range page.Items {
		if block.Index <= localHeight {
			continue
		}
		if block.Index > 0 {
			previous, err := loadGovRepresentativeBlock(block.Index - 1)
			if err != nil {
				return err
			}
			if err := validateGovUpperBlock(block, previous); err != nil {
				return err
			}
		}
		if err := saveGovRepresentativeBlock(block); err != nil {
			return err
		}
		localHeight = block.Index
		added++
	}
	if added > 0 {
		log.Printf("[Gov 대표][장부 동기화] Hos=%s, Gov리더=%s, 추가블록=%d, 최신높이=%d", selfID(), leader, added, localHeight)
	}
	return nil
}
