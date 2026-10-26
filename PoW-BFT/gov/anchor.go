package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

// Gov에서 Hos가 제출한 앵커를 수신하고 검증한 후 pending 추가함수 호출(부트노드만 수행)
// Gov에서 Hos가 제출한 앵커를 수신하고 검증한 후 pending 추가 (상위 체인용 최종 수정본)
func addAnchor(w http.ResponseWriter, r *http.Request) {
	var req GovAnchorSubmission
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	defer r.Body.Close()

	// 1. Hos의 공개키 가져오기
	resp, err := http.Get("http://" + req.HosBoot + "/getPublicKey")
	if err != nil {
		log.Printf("[ANCHOR][ERROR] failed to fetch public key from %s: %v", req.HosBoot, err)
		http.Error(w, "failed to fetch public key", 500)
		return
	}
	defer resp.Body.Close()

	pubPem, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read public key", 500)
		return
	}

	// 앵커와 대표 위임을 함께 검증하여 서로 다른 요청으로 바뀌지 않도록 한다.
	representative, err := buildPoWRepresentativeChange(req, string(pubPem))
	if err != nil {
		log.Printf("[ANCHOR][INVALID] %s: %v", req.HosID, err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// 검증된 대표 변경은 이 앵커를 담은 상위 블록이 확정된 뒤부터 적용된다.
	ar := AnchorRecord{
		HosID:            req.HosID,
		ContractSnapshot: ContractData{},
		LowerRoot:        req.Root,
		AccessCatalog:    []string{},
		AnchorTimestamp:  req.Ts,
		Representative:   representative,
	}

	appendPending([]AnchorRecord{ar})
	log.Printf("[ANCHOR] Verified & Pending anchor added")

	if err := saveAnchorToDB(req.HosID, req.Root, req.Ts); err != nil {
		log.Printf("[ANCHOR][ERROR] Failed to save anchor to DB for %s", req.HosID)
	}

	anchorMu.Lock()
	anchorMap[req.HosID] = AnchorInfo{Root: req.Root, Ts: req.Ts}
	anchorMu.Unlock()

	// 부트노드 정보 업데이트 체크
	if req.HosBoot != getHosBootAddr(req.HosID) {
		log.Printf("[ANCHOR] New HosBoot addr detected %s : %s", req.HosID, req.HosBoot)
		broadcastNewHosBoot(req.HosID, req.HosBoot)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                "pending",
		"representative_change": representative.Action,
		"activation":            "next_gov_block_after_registration",
	})
}

// Hos가 반환하는 검색 응답 구조체
type SearchResponse struct {
	Record     ClinicRecord `json:"record"`
	BlockRoot  string       `json:"block_root"`
	LatestRoot string       `json:"latest_root"`
	Leaf       string       `json:"leaf"`
	Proof      [][2]string  `json:"proof"`
}

// Hos 검색 프로세스 (핸들러에서 호출)
func handleHosSearch(hosID, keyword string) ([]byte, int, error) {

	// 1) Hos 부트 주소 조회
	hosAddr := getHosBootAddr(hosID)
	if hosAddr == "" {
		fmt.Println("[Search] Invalid Hos Boot Address")
		return nil, http.StatusBadGateway, nil
	}

	// 2) CP 체인에 검색 요청 (/search)
	items, err := requestHosSearch(hosAddr, keyword)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}

	// 3) Gov AnchorRoot + MerkleProof 검증
	verified, err := verifyHosResults(hosID, items)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// 4) JSON 반환
	out, _ := json.Marshal(verified)
	return out, http.StatusOK, nil
}

// CP /search 호출 (CP가 주는 JSON = []SearchResponse)
func requestHosSearch(hosAddr, keyword string) ([]SearchResponse, error) {

	url := fmt.Sprintf("http://%s/search?value=%s", hosAddr, url.QueryEscape(keyword))

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to reach CP node: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hos error: %s", string(b))
	}

	// SearchResponse 배열로 받는다
	var items []SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("invalid JSON from CP")
	}
	logInfo("[QUERY] Response From CP Chain : %d", len(items))
	return items, nil
}

// Gov -> CP 검색 결과 검증
func verifyHosResults(hosID string, items []SearchResponse) ([]SearchResponse, error) {
	// 1) Gov가 저장한 최신 AnchorRoot 조회
	anchorMu.RLock()
	anch, ok := anchorMap[hosID]
	anchorMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no anchor for hos_id=%s", hosID)
	}
	anchorRoot := anch.Root

	verified := []SearchResponse{}
	// 2) 결과별 검증 수행
	for _, it := range items {

		// 최신 블록 root 일치 여부
		if it.LatestRoot != anchorRoot {
			logInfo("[QUERY][ERROR] Anchor Root Mismatch")
			logInfo("[QUERY][ERROR] Latest=%s Anchor=%s", it.LatestRoot[:10], anchorRoot[:10])
			continue
		} else {
			logInfo("[QUERY] Success to Latest Anchor Verification ")
		}

		// 키워드가 포함된 블록의 Merkle 증명을 통한 유효성 검증
		if verifyMerkleProof(it.Leaf, it.Proof, it.BlockRoot) {
			verified = append(verified, it)
			logInfo("[QUERY][SUCCESS] Verified Record Appended")
		}
	}
	return verified, nil
}
