package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// HosRepresentative는 Gov 장부에서 확정된 하위체인 대표 검증자다.
type HosRepresentative struct {
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

// HosRepresentativeChange는 이 객체가 포함된 Gov 블록이 확정된 뒤 적용된다.
type HosRepresentativeChange struct {
	Action                 string            `json:"action"`
	Representative         HosRepresentative `json:"representative"`
	HosLeaderPublicKey     string            `json:"hos_leader_public_key"`
	AuthorizationSignature string            `json:"authorization_signature"`
}

type AnchorSubmission struct {
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

var (
	hosRepresentativeMap     = make(map[string]HosRepresentative)
	representativeKeyHistory = make(map[string]string)
	hosRepresentativeMapMu   sync.RWMutex
)

func anchorSubmissionDigest(req AnchorSubmission) []byte {
	payload := fmt.Sprintf("HOS-ANCHOR|v2|%s|%s|%d|%s|%s|%s|%s|%d|%s",
		req.HosID, req.HosBoot, req.LowerHeight, req.LowerBlockHash, req.Root,
		req.GovEndpoint, req.GovPublicKey, req.LeadershipTerm, req.Ts)
	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

func representativeChangeFromAnchor(req AnchorSubmission, leaderPublicKey string) (*HosRepresentativeChange, error) {
	rep := HosRepresentative{
		HosID: req.HosID, LeaderAddr: req.HosBoot, Endpoint: req.GovEndpoint,
		PublicKey: req.GovPublicKey, LeadershipTerm: req.LeadershipTerm,
		LowerHeight: req.LowerHeight, LowerBlockHash: req.LowerBlockHash,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := validateRepresentativeFields(rep); err != nil {
		return nil, err
	}
	hosRepresentativeMapMu.RLock()
	current, exists := hosRepresentativeMap[req.HosID]
	hosRepresentativeMapMu.RUnlock()
	action := "ADD"
	if exists {
		if rep.LowerHeight <= current.LowerHeight || rep.LeadershipTerm < current.LeadershipTerm {
			return nil, fmt.Errorf("과거 또는 중복된 대표 정보입니다: 현재높이=%d 요청높이=%d", current.LowerHeight, rep.LowerHeight)
		}
		action = "REFRESH"
		if current.Endpoint != rep.Endpoint || current.PublicKey != rep.PublicKey || current.LeaderAddr != rep.LeaderAddr {
			action = "REPLACE"
		}
	}
	return &HosRepresentativeChange{
		Action: action, Representative: rep, HosLeaderPublicKey: leaderPublicKey,
		AuthorizationSignature: req.Sig,
	}, nil
}

func validateRepresentativeFields(rep HosRepresentative) error {
	if rep.HosID == "" || rep.LeaderAddr == "" || rep.Endpoint == "" || rep.PublicKey == "" || rep.LowerHeight <= 0 {
		return fmt.Errorf("Hos 대표 필수 정보가 비어 있습니다")
	}
	if rep.Endpoint != strings.TrimRight(rep.LeaderAddr, "/")+"/gov" {
		return fmt.Errorf("Gov 대표 엔드포인트는 Hos 리더 주소의 /gov 경로여야 합니다")
	}
	return nil
}

func anchorRequestFromRecord(record AnchorRecord, change HosRepresentativeChange) AnchorSubmission {
	rep := change.Representative
	return AnchorSubmission{
		HosID: rep.HosID, HosBoot: rep.LeaderAddr, Root: record.LowerRoot,
		Ts: record.AnchorTimestamp, Sig: change.AuthorizationSignature,
		LowerHeight: rep.LowerHeight, LowerBlockHash: rep.LowerBlockHash,
		GovEndpoint: rep.Endpoint, GovPublicKey: rep.PublicKey, LeadershipTerm: rep.LeadershipTerm,
	}
}

func validateRepresentativeChanges(records []AnchorRecord) error {
	hosRepresentativeMapMu.RLock()
	virtual := make(map[string]HosRepresentative, len(hosRepresentativeMap))
	for hosID, rep := range hosRepresentativeMap {
		virtual[hosID] = rep
	}
	hosRepresentativeMapMu.RUnlock()

	for _, record := range records {
		if record.Representative == nil {
			continue
		}
		change := *record.Representative
		rep := change.Representative
		if err := validateRepresentativeFields(rep); err != nil {
			return err
		}
		expectedAction := "ADD"
		if current, exists := virtual[rep.HosID]; exists {
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
		req := anchorRequestFromRecord(record, change)
		if !verifyECDSA(change.HosLeaderPublicKey, anchorSubmissionDigest(req), change.AuthorizationSignature) {
			return fmt.Errorf("Hos %s 대표 위임 서명이 유효하지 않습니다", rep.HosID)
		}
		virtual[rep.HosID] = rep
	}
	return nil
}

func computeRepresentativeChangesHash(records []AnchorRecord) string {
	changes := make([]HosRepresentativeChange, 0)
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

func applyRepresentativeChangesFromBlock(block UpperBlock) error {
	for _, record := range block.Records {
		if record.Representative == nil {
			continue
		}
		change := *record.Representative
		rep := change.Representative
		rep.ActivationHeight = block.Index
		data, err := json.Marshal(rep)
		if err != nil {
			return err
		}
		if err := db.Put([]byte("hos_representative_"+rep.HosID), data, nil); err != nil {
			return err
		}
		if err := db.Put([]byte("hos_representative_key_"+rep.Endpoint), []byte(rep.PublicKey), nil); err != nil {
			return err
		}
		hosRepresentativeMapMu.Lock()
		previous, replaced := hosRepresentativeMap[rep.HosID]
		hosRepresentativeMap[rep.HosID] = rep
		representativeKeyHistory[rep.Endpoint] = rep.PublicKey
		if replaced {
			representativeKeyHistory[previous.Endpoint] = previous.PublicKey
		}
		hosRepresentativeMapMu.Unlock()
		setHosBootAddr(rep.HosID, rep.LeaderAddr)
		log.Printf("[Gov 대표][%s 확정] Hos=%s, 리더=%s, 합의주소=%s, 활성높이=%d, 다음 Gov 합의부터 참여",
			change.Action, rep.HosID, rep.LeaderAddr, rep.Endpoint, block.Index)
	}
	return nil
}

func loadHosRepresentativesAtBoot() {
	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		key := string(iter.Key())
		if strings.HasPrefix(key, "hos_representative_key_") {
			representativeKeyHistory[strings.TrimPrefix(key, "hos_representative_key_")] = string(iter.Value())
			continue
		}
		if !strings.HasPrefix(key, "hos_representative_") {
			continue
		}
		var rep HosRepresentative
		if err := json.Unmarshal(iter.Value(), &rep); err != nil {
			log.Printf("[Gov 대표][복구 경고] %s: %v", key, err)
			continue
		}
		hosRepresentativeMap[rep.HosID] = rep
		representativeKeyHistory[rep.Endpoint] = rep.PublicKey
		hosBootMap[rep.HosID] = rep.LeaderAddr
		log.Printf("[Gov 대표][복구] Hos=%s, 리더=%s, 합의주소=%s", rep.HosID, rep.LeaderAddr, rep.Endpoint)
	}
}

func representativeEndpoints() []string {
	hosRepresentativeMapMu.RLock()
	defer hosRepresentativeMapMu.RUnlock()
	out := make([]string, 0, len(hosRepresentativeMap))
	for _, rep := range hosRepresentativeMap {
		out = append(out, rep.Endpoint)
	}
	sort.Strings(out)
	return out
}

func representativePublicKey(endpoint string) (string, bool) {
	hosRepresentativeMapMu.RLock()
	defer hosRepresentativeMapMu.RUnlock()
	key, ok := representativeKeyHistory[endpoint]
	return key, ok && key != ""
}

func isHosRepresentativeEndpoint(endpoint string) bool {
	for _, current := range representativeEndpoints() {
		if current == endpoint {
			return true
		}
	}
	return false
}

func representativeSnapshot() map[string]HosRepresentative {
	hosRepresentativeMapMu.RLock()
	defer hosRepresentativeMapMu.RUnlock()
	out := make(map[string]HosRepresentative, len(hosRepresentativeMap))
	for id, rep := range hosRepresentativeMap {
		out[id] = rep
	}
	return out
}

func consensusValidatorKeys() map[string]string {
	keys := make(map[string]string)
	if key, ok := getMeta("meta_gov_pubkey"); ok {
		keys[self] = key
	}
	pkMu.RLock()
	for addr, key := range peerPubKeys {
		keys[addr] = key
	}
	pkMu.RUnlock()
	hosRepresentativeMapMu.RLock()
	for _, rep := range hosRepresentativeMap {
		keys[rep.Endpoint] = rep.PublicKey
	}
	hosRepresentativeMapMu.RUnlock()
	return keys
}

func handleConsensusValidators(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET 요청만 허용됩니다", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"gov_id": selfID(), "leader": getBootAddr(),
		"participants": consensusParticipants(), "public_keys": consensusValidatorKeys(),
	})
}
