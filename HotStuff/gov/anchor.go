package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// 개인키, 공개키 자동 생성 (최초 실행 시)
func ensureKeyPair() {
	if _, ok := getMeta("meta_gov_privkey"); ok {
		return
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)

	privPem := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))
	pubPem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	putMeta("meta_gov_privkey", privPem)
	putMeta("meta_gov_pubkey", pubPem)
	log.Println("[앵커][초기화] Gov 노드용 ECDSA P-256 키 쌍을 생성했습니다.")
}

// makeAnchorSignature는 HotStuff 투표 digest(32바이트 hex)를 DER ECDSA로 서명한다.
func makeAnchorSignature(privPem, hashStr, _ string) string {
	block, _ := pem.Decode([]byte(privPem))
	if block == nil {
		return ""
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return ""
	}
	digest, err := hex.DecodeString(hashStr)
	if err != nil {
		return ""
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return ""
	}
	encoded, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return ""
	}
	return hex.EncodeToString(encoded)
}

// Gov에서 Hos가 제출한 앵커를 수신하고 검증한 후 pending 추가함수 호출(부트노드만 수행)
func addAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 요청만 허용됩니다", http.StatusMethodNotAllowed)
		return
	}
	var req AnchorSubmission
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	defer r.Body.Close()
	if req.HosID == "" || req.HosBoot == "" || req.Root == "" || req.Sig == "" ||
		req.LowerHeight <= 0 || req.LowerBlockHash == "" || req.GovEndpoint == "" || req.GovPublicKey == "" {
		http.Error(w, "앵커 또는 Gov 대표 필수 정보가 비어 있습니다", http.StatusBadRequest)
		return
	}

	// Hos의 공개키 가져오기
	resp, err := http.Get("http://" + req.HosBoot + "/getPublicKey")
	if err != nil {
		http.Error(w, "failed to fetch public key", 500)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Hos 리더 공개키 조회가 거부되었습니다", http.StatusBadGateway)
		return
	}

	// Hos 노드로부터 전송받은 공개키(PEM 형식)를 전체 읽음
	pubPem, _ := io.ReadAll(resp.Body)

	if !verifyECDSA(string(pubPem), anchorSubmissionDigest(req), req.Sig) {
		http.Error(w, "앵커/대표 위임 서명이 유효하지 않습니다", http.StatusForbidden)
		log.Printf("[앵커][거부] Hos=%s의 대표 위임 서명이 유효하지 않습니다.", req.HosID)
		return
	}
	change, err := representativeChangeFromAnchor(req, string(pubPem))
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		log.Printf("[Gov 대표][변경 거부] Hos=%s, 사유=%v", req.HosID, err)
		return
	}
	log.Printf("[Gov 대표][%s 대기] Hos=%s, 리더=%s, 합의주소=%s, 하위높이=%d. 이번 Gov 블록 확정 후 활성화됩니다.",
		change.Action, req.HosID, req.HosBoot, req.GovEndpoint, req.LowerHeight)

	// AnchorRecord 구성 (계약 정보는 현재 비워둠)
	ar := AnchorRecord{
		HosID:            req.HosID,
		ContractSnapshot: ContractData{}, // 빈 계약 정보
		LowerRoot:        req.Root,
		AccessCatalog:    []string{}, // 비어있는 접근 리스트
		AnchorTimestamp:  req.Ts,
		Representative:   change,
	}

	// pending 에 anchor 객체 전체 추가
	appendPending([]AnchorRecord{ar})
	log.Printf("[앵커][대기열] Hos=%s, 하위블록=%d, 루트=%s, Gov대표=%s",
		req.HosID, req.LowerHeight, shortHash(req.Root), req.GovEndpoint)

	// AnchorRoot LevelDB 저장
	if err := saveAnchorToDB(req.HosID, req.Root, req.Ts); err != nil {
		log.Printf("[ANCHOR][ERROR] Failed to save anchor to DB for %s", req.HosID)
	} else {
		log.Printf("[ANCHOR][DB] Success to save anchor to DB for %s", req.HosID)
	}

	// 전역변수에 저장
	anchorMu.Lock()
	anchorMap[req.HosID] = AnchorInfo{Root: req.Root, Ts: req.Ts}
	anchorMu.Unlock()

	// 앵커 저장
	log.Printf("[ANCHOR] Verified & adding anchor from Hos Chain ... %s : %s)", req.HosID, anchorMap[req.HosID].Root)

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ACCEPTED", "representative_change": change.Action,
		"gov_endpoint": req.GovEndpoint, "activation": "AFTER_CURRENT_GOV_BLOCK",
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

// Gov -> Hos 검색 결과 검증
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

// 서명 검증 로직
func verifyECDSA(pubPemStr string, hash []byte, sigHex string) bool {
	if pubPemStr == "" {
		return false
	}

	block, _ := pem.Decode([]byte(pubPemStr))
	if block == nil {
		return false
	}

	pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	pubKey, ok := pubIfc.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	var sigStruct struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(sigBytes, &sigStruct)
	if err != nil {
		return false
	}

	return ecdsa.Verify(pubKey, hash, sigStruct.R, sigStruct.S)
}
