package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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

const govPoWHashHexLength = sha256.Size * 2

type GovPoWHeader struct {
	Index             int    `json:"index"`
	PrevHash          string `json:"prev_hash"`
	MerkleRoot        string `json:"merkle_root"`
	ConfigurationHash string `json:"configuration_hash,omitempty"`
	Timestamp         string `json:"timestamp"`
	Difficulty        int    `json:"difficulty"`
	Nonce             uint64 `json:"nonce"`
}

type govMineResult struct {
	BlockHash string
	Header    GovPoWHeader
	Elapsed   float32
}

type govBlocksPage struct {
	Total      int          `json:"total"`
	Items      []UpperBlock `json:"items"`
	Difficulty int          `json:"difficulty"`
}

var (
	govRepresentativeMining atomic.Bool
	govRepresentativeStop   atomic.Bool
	govRepresentativeMu     sync.Mutex
	govRepresentativeLatest UpperBlock
	govRepresentativeState  = make(map[string]PoWRepresentative)
	govRepresentativeHTTP   = &http.Client{Timeout: 5 * time.Second}
)

func govRepresentativeEndpoint() string {
	return strings.TrimSuffix(self, "/") + "/gov"
}

func isCurrentHosLeader() bool {
	return self != "" && self == getBootAddr()
}

func computeGovRepresentativeChangesHash(records []AnchorRecord) string {
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

func computeUpperMerkleRoot(records []AnchorRecord) string {
	if len(records) == 0 {
		return ""
	}
	leaves := make([]string, len(records))
	for i, record := range records {
		leaves[i] = record.LowerRoot
	}
	return merkleRootHex(leaves)
}

func computeGovPoWHash(header GovPoWHeader) string {
	b, _ := json.Marshal(header)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func validGovPoWHash(hash string, difficulty int) bool {
	return len(hash) == govPoWHashHexLength && difficulty >= 1 &&
		difficulty <= govPoWHashHexLength && strings.HasPrefix(hash, strings.Repeat("0", difficulty))
}

func randomGovNonce() uint64 {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(fmt.Sprintf("안전한 Gov PoW Nonce 생성 실패: %v", err))
	}
	return binary.BigEndian.Uint64(value[:])
}

func loadGovChainSnapshot() (govBlocksPage, error) {
	addr := getGovBoot()
	if addr == "" {
		return govBlocksPage{}, fmt.Errorf("Gov 부트노드 주소가 없습니다")
	}
	url := "http://" + addr + "/blocks?offset=0&limit=1000000"
	resp, err := govRepresentativeHTTP.Get(url)
	if err != nil {
		return govBlocksPage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return govBlocksPage{}, fmt.Errorf("Gov 장부 조회 실패: status=%d body=%s", resp.StatusCode, string(body))
	}
	var page govBlocksPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return govBlocksPage{}, err
	}
	if len(page.Items) == 0 || page.Total != len(page.Items) {
		return govBlocksPage{}, fmt.Errorf("Gov 장부 스냅샷이 완전하지 않습니다: total=%d items=%d", page.Total, len(page.Items))
	}
	state := make(map[string]PoWRepresentative)
	for i := 1; i < len(page.Items); i++ {
		if err := validateGovUpperBlock(page.Items[i], page.Items[i-1]); err != nil {
			return govBlocksPage{}, fmt.Errorf("Gov 블록 #%d 검증 실패: %w", page.Items[i].Index, err)
		}
		if err := validateGovRepresentativeChanges(page.Items[i].Records, state); err != nil {
			return govBlocksPage{}, fmt.Errorf("Gov 블록 #%d 대표 변경 검증 실패: %w", page.Items[i].Index, err)
		}
	}
	govRepresentativeMu.Lock()
	govRepresentativeLatest = page.Items[len(page.Items)-1]
	govRepresentativeState = state
	govRepresentativeMu.Unlock()
	return page, nil
}

func validateGovRepresentativeChanges(records []AnchorRecord, state map[string]PoWRepresentative) error {
	for _, record := range records {
		if record.Representative == nil {
			continue
		}
		change := *record.Representative
		rep := change.Representative
		if rep.HosID == "" || rep.HosID != record.HosID || rep.LeaderAddr == "" || rep.Endpoint == "" ||
			rep.LowerHeight <= 0 || rep.LowerBlockHash == "" || rep.LeadershipTerm == 0 {
			return fmt.Errorf("대표 필수 정보가 비어 있거나 앵커 Hos ID와 다릅니다")
		}
		if rep.Endpoint != strings.TrimSuffix(rep.LeaderAddr, "/")+"/gov" {
			return fmt.Errorf("대표 엔드포인트가 하위체인 리더 주소와 일치하지 않습니다")
		}
		expectedAction := "ADD"
		if current, exists := state[rep.HosID]; exists {
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
		req := GovAnchorSubmission{
			HosID: rep.HosID, HosBoot: rep.LeaderAddr, Root: record.LowerRoot,
			Ts: record.AnchorTimestamp, Sig: change.AuthorizationSignature,
			LowerHeight: rep.LowerHeight, LowerBlockHash: rep.LowerBlockHash,
			GovEndpoint: rep.Endpoint, LeadershipTerm: rep.LeadershipTerm,
		}
		if !verifyECDSA(change.HosLeaderPublicKey, govAnchorSubmissionDigest(req), change.AuthorizationSignature) {
			return fmt.Errorf("대표 위임 서명이 올바르지 않습니다")
		}
		state[rep.HosID] = rep
	}
	return nil
}

func validateGovUpperBlock(block, prev UpperBlock) error {
	if block.Index != prev.Index+1 || block.PrevHash != prev.BlockHash || block.GovID != prev.GovID {
		return fmt.Errorf("상위체인 연결 정보가 일치하지 않습니다")
	}
	if block.MerkleRoot != computeUpperMerkleRoot(block.Records) {
		return fmt.Errorf("상위 머클루트가 일치하지 않습니다")
	}
	if block.ConfigurationHash != computeGovRepresentativeChangesHash(block.Records) {
		return fmt.Errorf("대표 구성 해시가 일치하지 않습니다")
	}
	header := GovPoWHeader{
		Index: block.Index, PrevHash: block.PrevHash, MerkleRoot: block.MerkleRoot,
		ConfigurationHash: block.ConfigurationHash, Timestamp: block.Timestamp,
		Difficulty: block.Difficulty, Nonce: block.Nonce,
	}
	if computeGovPoWHash(header) != block.BlockHash || !validGovPoWHash(block.BlockHash, block.Difficulty) {
		return fmt.Errorf("상위 PoW 검증에 실패했습니다")
	}
	return nil
}

func handleGovRepresentativeMineStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isCurrentHosLeader() {
		http.Error(w, "only the current Hos leader can mine Gov blocks", http.StatusForbidden)
		return
	}
	var req PoWMiningRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if len(req.Anchors) == 0 || req.Difficulty < 1 || req.Difficulty > govPoWHashHexLength {
		http.Error(w, "invalid mining request", http.StatusBadRequest)
		return
	}
	endpoint := govRepresentativeEndpoint()
	authorized := false
	for _, participant := range req.Participants {
		if participant == endpoint {
			authorized = true
			break
		}
	}
	if !authorized {
		http.Error(w, "representative is not in the committed participant set", http.StatusForbidden)
		return
	}
	page, err := loadGovChainSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if !govRepresentativeMining.CompareAndSwap(false, true) {
		writeRepresentativeJSON(w, http.StatusConflict, map[string]string{"status": "already mining"})
		return
	}
	govRepresentativeStop.Store(false)
	latest := page.Items[len(page.Items)-1]
	participants := append([]string(nil), req.Participants...)
	anchors := append([]AnchorRecord(nil), req.Anchors...)
	go func() {
		defer govRepresentativeMining.Store(false)
		result := mineGovRepresentativeBlock(latest, req.Difficulty, anchors)
		if result.BlockHash == "" {
			return
		}
		nextDifficulty := nextGovDifficulty(page.Items, result.Header.Index, result.Elapsed, req.Difficulty)
		broadcastGovRepresentativeBlock(result, anchors, participants, nextDifficulty)
	}()
	writeRepresentativeJSON(w, http.StatusAccepted, map[string]string{"status": "mining started"})
}

func mineGovRepresentativeBlock(prev UpperBlock, difficulty int, anchors []AnchorRecord) govMineResult {
	start := time.Now()
	header := GovPoWHeader{
		Index: prev.Index + 1, PrevHash: prev.BlockHash,
		MerkleRoot:        computeUpperMerkleRoot(anchors),
		ConfigurationHash: computeGovRepresentativeChangesHash(anchors),
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano), Difficulty: difficulty,
	}
	startNonce := randomGovNonce()
	nonce := startNonce
	for !govRepresentativeStop.Load() {
		header.Nonce = nonce
		hash := computeGovPoWHash(header)
		if validGovPoWHash(hash, difficulty) {
			return govMineResult{BlockHash: hash, Header: header, Elapsed: float32(time.Since(start).Seconds())}
		}
		nonce++
		if nonce == startNonce {
			header.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
			startNonce = randomGovNonce()
			nonce = startNonce
		}
	}
	return govMineResult{}
}

func nextGovDifficulty(blocks []UpperBlock, index int, elapsed float32, current int) int {
	e := [3]float32{}
	e[2] = elapsed
	if index > 2 && len(blocks) >= 2 {
		e[1] = blocks[len(blocks)-1].Elapsed
		e[0] = blocks[len(blocks)-2].Elapsed
	}
	ratio := float64(e[0]+e[1]+e[2]) / 3.0 / 20.0
	if ratio < 0.85 && current < 7 {
		return current + 1
	}
	if ratio > 1.25 && current > 1 {
		return current - 1
	}
	return current
}

func broadcastGovRepresentativeBlock(result govMineResult, anchors []AnchorRecord, participants []string, nextDifficulty int) {
	body, _ := json.Marshal(map[string]any{
		"header": result.Header, "hash": result.BlockHash, "entries": anchors,
		"difficulty": nextDifficulty, "elapsed": result.Elapsed, "winner": self,
	})
	unique := make(map[string]struct{})
	for _, participant := range participants {
		unique[participant] = struct{}{}
	}
	ordered := make([]string, 0, len(unique))
	for participant := range unique {
		ordered = append(ordered, participant)
	}
	sort.Strings(ordered)
	for _, participant := range ordered {
		go func(addr string) {
			resp, err := govRepresentativeHTTP.Post("http://"+addr+"/receiveBlock", "application/json", bytes.NewReader(body))
			if err != nil {
				log.Printf("[GOV-POW][REPRESENTATIVE] %s 블록 전파 실패: %v", addr, err)
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}(participant)
	}
	log.Printf("[GOV-POW][REPRESENTATIVE] 상위 블록 #%d 채굴 성공 hash=%s elapsed=%.4fs",
		result.Header.Index, result.BlockHash[:12], result.Elapsed)
}

func handleGovRepresentativeReceiveBlock(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		Header  GovPoWHeader   `json:"header"`
		Hash    string         `json:"hash"`
		Anchors []AnchorRecord `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	govRepresentativeMu.Lock()
	prev := govRepresentativeLatest
	state := make(map[string]PoWRepresentative, len(govRepresentativeState))
	for hosID, representative := range govRepresentativeState {
		state[hosID] = representative
	}
	govRepresentativeMu.Unlock()
	if prev.BlockHash == "" || msg.Header.Index != prev.Index+1 || msg.Header.PrevHash != prev.BlockHash {
		page, err := loadGovChainSnapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		prev = page.Items[len(page.Items)-1]
		if prev.BlockHash == msg.Hash && prev.Index == msg.Header.Index {
			govRepresentativeStop.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		govRepresentativeMu.Lock()
		state = make(map[string]PoWRepresentative, len(govRepresentativeState))
		for hosID, representative := range govRepresentativeState {
			state[hosID] = representative
		}
		govRepresentativeMu.Unlock()
	}
	block := UpperBlock{
		Index: msg.Header.Index, GovID: prev.GovID, PrevHash: msg.Header.PrevHash,
		Timestamp: msg.Header.Timestamp, Records: msg.Anchors, MerkleRoot: msg.Header.MerkleRoot,
		ConfigurationHash: msg.Header.ConfigurationHash, Nonce: msg.Header.Nonce,
		Difficulty: msg.Header.Difficulty, BlockHash: msg.Hash,
	}
	if err := validateGovUpperBlock(block, prev); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateGovRepresentativeChanges(block.Records, state); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	govRepresentativeStop.Store(true)
	govRepresentativeMu.Lock()
	govRepresentativeLatest = block
	govRepresentativeState = state
	govRepresentativeMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func handleGovRepresentativeStatus(w http.ResponseWriter, r *http.Request) {
	writeRepresentativeJSON(w, http.StatusOK, map[string]any{
		"endpoint": govRepresentativeEndpoint(), "leader": isCurrentHosLeader(),
		"mining": govRepresentativeMining.Load(),
	})
}

func writeRepresentativeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
