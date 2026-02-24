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
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
)

// Gov에서 Hos가 제출한 앵커를 수신하고 검증한 후 pending 추가함수 호출(부트노드만 수행)
// Gov에서 Hos가 제출한 앵커를 수신하고 검증한 후 pending 추가 (상위 체인용 수정본)
func addAnchor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HosID   string `json:"hos_id"`
		HosBoot string `json:"hos_boot"`
		Root    string `json:"root"`
		Ts      string `json:"ts"`
		Sig     string `json:"sig"`
	}
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

	// 2. ECDSA 공개키 파싱 (하위 체인과 규격 일치)
	block, _ := pem.Decode(pubPem)
	if block == nil {
		log.Printf("[ANCHOR][ERROR] failed to decode PEM for %s", req.HosID)
		http.Error(w, "invalid public key pem", 400)
		return
	}
	pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("[ANCHOR][ERROR] failed to parse PKIX for %s: %v", req.HosID, err)
		http.Error(w, "invalid public key format", 400)
		return
	}
	pubKey, ok := pubIfc.(*ecdsa.PublicKey)
	if !ok {
		http.Error(w, "not an ecdsa public key", 400)
		return
	}

	// 3. 서명 검증을 위한 해시 계산 (하위 체인 전송 규격과 일치)
	msg := []byte(req.Root + "|" + req.Ts)
	hash := sha256.Sum256(msg)

	// 4. DER 디코딩 및 검증 (가장 중요한 수정 부분)
	sigBytes, err := hex.DecodeString(req.Sig)
	if err != nil {
		http.Error(w, "invalid hex signature", 400)
		return
	}

	var sigStruct struct {
		R, S *big.Int
	}
	// 하위 체인에서 asn1.Marshal로 보낸 데이터를 정확히 언마샬링함
	if _, err := asn1.Unmarshal(sigBytes, &sigStruct); err != nil {
		log.Printf("[ANCHOR][ERROR] ASN1 Unmarshal fail for %s: %v", req.HosID, err)
		http.Error(w, "invalid signature format", 403)
		return
	}

	// 실제 ECDSA 검증 수행
	if !ecdsa.Verify(pubKey, hash[:], sigStruct.R, sigStruct.S) {
		log.Printf("[ANCHOR][INVALID] Signature verification failed from %s", req.HosID)
		http.Error(w, "invalid signature", 403)
		return
	}

	// 5. AnchorRecord 구성 및 저장 (기본 로직 유지)
	ar := AnchorRecord{
		HosID:            req.HosID,
		ContractSnapshot: ContractData{},
		LowerRoot:        req.Root,
		AccessCatalog:    []string{},
		AnchorTimestamp:  req.Ts,
	}

	appendPending([]AnchorRecord{ar})
	log.Printf("[ANCHOR] Pending anchor added: %+v", ar)

	if err := saveAnchorToDB(req.HosID, req.Root, req.Ts); err != nil {
		log.Printf("[ANCHOR][ERROR] Failed to save anchor to DB for %s", req.HosID)
	} else {
		log.Printf("[ANCHOR][DB] Success to save anchor to DB for %s", req.HosID)
	}

	anchorMu.Lock()
	anchorMap[req.HosID] = AnchorInfo{Root: req.Root, Ts: req.Ts}
	anchorMu.Unlock()

	log.Printf("[ANCHOR] Verified & adding anchor from Hos Chain %s : %s", req.HosID, req.Root)

	// 부트노드 정보 업데이트 체크
	if req.HosBoot != getHosBootAddr(req.HosID) {
		log.Printf("[ANCHOR] New HosBoot addr detected %s : %s", req.HosID, req.HosBoot)
		broadcastNewHosBoot(req.HosID, req.HosBoot)
	}
	w.WriteHeader(http.StatusOK)
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
