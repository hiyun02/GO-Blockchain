package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
)

var (
	powRepresentativeMu  sync.RWMutex
	powRepresentativeMap = make(map[string]PoWRepresentative)
)

// Gov 앵커와 대표 위임 정보를 하나의 서명 대상으로 묶는다.
func govAnchorSubmissionDigest(req GovAnchorSubmission) []byte {
	payload := fmt.Sprintf("HOS-POW-ANCHOR|v2|%s|%s|%s|%s|%d|%s|%s|%d",
		req.HosID, req.HosBoot, req.Root, req.Ts, req.LowerHeight,
		req.LowerBlockHash, req.GovEndpoint, req.LeadershipTerm)
	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

func verifyRepresentativeSignature(publicKey string, req GovAnchorSubmission) bool {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sigBytes, err := hex.DecodeString(req.Sig)
	if err != nil {
		return false
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil || sig.R == nil || sig.S == nil {
		return false
	}
	return ecdsa.Verify(pub, govAnchorSubmissionDigest(req), sig.R, sig.S)
}

// 대표 변경만 별도로 해시하여 PoW 헤더가 채굴 참가자 구성도 봉인하도록 한다.
func computePoWRepresentativeChangesHash(records []AnchorRecord) string {
	changes := make([]PoWRepresentativeChange, 0)
	for _, record := range records {
		if record.Representative != nil {
			changes = append(changes, *record.Representative)
		}
	}
	if len(changes) == 0 {
		return ""
	}
	b, _ := json.Marshal(changes)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func representativeRequest(change PoWRepresentativeChange, record AnchorRecord) GovAnchorSubmission {
	rep := change.Representative
	return GovAnchorSubmission{
		HosID: rep.HosID, HosBoot: rep.LeaderAddr, Root: record.LowerRoot,
		Ts: record.AnchorTimestamp, Sig: change.AuthorizationSignature,
		LowerHeight: rep.LowerHeight, LowerBlockHash: rep.LowerBlockHash,
		GovEndpoint: rep.Endpoint, LeadershipTerm: rep.LeadershipTerm,
	}
}

func applyRepresentativeChange(state map[string]PoWRepresentative, change PoWRepresentativeChange, height int) {
	rep := change.Representative
	rep.ActivationHeight = height
	state[rep.HosID] = rep
}

func representativeStateAt(height int) (map[string]PoWRepresentative, error) {
	state := make(map[string]PoWRepresentative)
	for i := 1; i <= height; i++ {
		block, err := getBlockByIndex(i)
		if err != nil {
			return nil, err
		}
		for _, record := range block.Records {
			if record.Representative != nil {
				applyRepresentativeChange(state, *record.Representative, block.Index)
			}
		}
	}
	return state, nil
}

func validateRepresentativeChange(state map[string]PoWRepresentative, record AnchorRecord) error {
	change := record.Representative
	if change == nil {
		return nil
	}
	rep := change.Representative
	if rep.HosID == "" || rep.HosID != record.HosID || rep.LeaderAddr == "" || rep.Endpoint == "" {
		return fmt.Errorf("대표 식별 정보가 올바르지 않습니다")
	}
	if rep.Endpoint != strings.TrimSuffix(rep.LeaderAddr, "/")+"/gov" {
		return fmt.Errorf("대표 엔드포인트가 하위체인 리더 주소와 일치하지 않습니다")
	}
	if rep.LowerHeight < 0 || rep.LowerBlockHash == "" || rep.LeadershipTerm == 0 {
		return fmt.Errorf("대표 위임 기준 블록 정보가 올바르지 않습니다")
	}
	current, exists := state[rep.HosID]
	expectedAction := "ADD"
	if exists {
		expectedAction = "REFRESH"
		if current.LeaderAddr != rep.LeaderAddr {
			expectedAction = "REPLACE"
		}
		if rep.LowerHeight <= current.LowerHeight || rep.LeadershipTerm <= current.LeadershipTerm {
			return fmt.Errorf("이전 대표 위임보다 오래된 요청입니다")
		}
	}
	if change.Action != expectedAction {
		return fmt.Errorf("대표 변경 동작 불일치: want=%s got=%s", expectedAction, change.Action)
	}
	if !verifyRepresentativeSignature(change.HosLeaderPublicKey, representativeRequest(*change, record)) {
		return fmt.Errorf("대표 위임 서명이 올바르지 않습니다")
	}
	applyRepresentativeChange(state, *change, 0)
	return nil
}

func validatePoWRepresentativeChanges(records []AnchorRecord, previousHeight int) error {
	state, err := representativeStateAt(previousHeight)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := validateRepresentativeChange(state, record); err != nil {
			return err
		}
	}
	return nil
}

func representativeStateWithPending() (map[string]PoWRepresentative, error) {
	height, ok := getLatestHeight()
	if !ok {
		return nil, fmt.Errorf("상위체인 높이를 확인할 수 없습니다")
	}
	state, err := representativeStateAt(height)
	if err != nil {
		return nil, err
	}
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	for _, record := range ch.pending {
		if record.Representative != nil {
			applyRepresentativeChange(state, *record.Representative, 0)
		}
	}
	return state, nil
}

func buildPoWRepresentativeChange(req GovAnchorSubmission, publicKey string) (*PoWRepresentativeChange, error) {
	if req.HosID == "" || req.HosBoot == "" || req.Root == "" || req.Ts == "" || req.Sig == "" {
		return nil, fmt.Errorf("필수 앵커 값이 비어 있습니다")
	}
	if len(req.Root) != sha256HexLength || len(req.LowerBlockHash) != sha256HexLength {
		return nil, fmt.Errorf("하위체인 루트 또는 블록 해시 길이가 올바르지 않습니다")
	}
	if _, err := hex.DecodeString(req.Root); err != nil {
		return nil, fmt.Errorf("하위체인 루트가 16진수 형식이 아닙니다")
	}
	if _, err := hex.DecodeString(req.LowerBlockHash); err != nil {
		return nil, fmt.Errorf("하위체인 블록 해시가 16진수 형식이 아닙니다")
	}
	if req.LowerHeight <= 0 || req.LeadershipTerm == 0 {
		return nil, fmt.Errorf("하위체인 높이 또는 리더 임기가 올바르지 않습니다")
	}
	if req.GovEndpoint != strings.TrimSuffix(req.HosBoot, "/")+"/gov" {
		return nil, fmt.Errorf("대표 엔드포인트가 하위체인 리더 주소와 일치하지 않습니다")
	}
	if !verifyRepresentativeSignature(publicKey, req) {
		return nil, fmt.Errorf("앵커 및 대표 위임 서명이 올바르지 않습니다")
	}
	state, err := representativeStateWithPending()
	if err != nil {
		return nil, err
	}
	action := "ADD"
	if current, ok := state[req.HosID]; ok {
		action = "REFRESH"
		if current.LeaderAddr != req.HosBoot {
			action = "REPLACE"
		}
		if req.LowerHeight <= current.LowerHeight || req.LeadershipTerm <= current.LeadershipTerm {
			return nil, fmt.Errorf("이미 처리된 하위체인 높이 또는 리더 임기입니다")
		}
	}
	return &PoWRepresentativeChange{
		Action: action,
		Representative: PoWRepresentative{
			HosID: req.HosID, LeaderAddr: req.HosBoot, Endpoint: req.GovEndpoint,
			LeadershipTerm: req.LeadershipTerm, LowerHeight: req.LowerHeight,
			LowerBlockHash: req.LowerBlockHash, RegisteredAt: req.Ts,
		},
		HosLeaderPublicKey: publicKey, AuthorizationSignature: req.Sig,
	}, nil
}

func applyPoWRepresentativeChanges(block UpperBlock) {
	powRepresentativeMu.Lock()
	defer powRepresentativeMu.Unlock()
	for _, record := range block.Records {
		if record.Representative != nil {
			applyRepresentativeChange(powRepresentativeMap, *record.Representative, block.Index)
		}
	}
}

func loadPoWRepresentativesAtBoot() error {
	height, ok := getLatestHeight()
	if !ok {
		return nil
	}
	state, err := representativeStateAt(height)
	if err != nil {
		return err
	}
	powRepresentativeMu.Lock()
	powRepresentativeMap = state
	powRepresentativeMu.Unlock()
	return nil
}

func miningParticipants() []string {
	unique := map[string]struct{}{self: {}}
	for _, peer := range peersSnapshot() {
		unique[peer] = struct{}{}
	}
	powRepresentativeMu.RLock()
	for _, rep := range powRepresentativeMap {
		unique[rep.Endpoint] = struct{}{}
	}
	powRepresentativeMu.RUnlock()
	participants := make([]string, 0, len(unique))
	for addr := range unique {
		if addr != "" {
			participants = append(participants, addr)
		}
	}
	sort.Strings(participants)
	return participants
}

func handleConsensusMiners(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"participants": miningParticipants(),
		"difficulty":   GlobalDifficulty,
	})
}
