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

// OTT에서 CP가 제출한 앵커를 수신하고 검증한 후 pending 추가함수 호출(부트노드만 수행)
func addAnchor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CpID   string `json:"cp_id"`
		CpBoot string `json:"cp_boot"`
		Root   string `json:"root"`
		Ts     string `json:"ts"`
		Sig    string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	defer r.Body.Close()

	// CP의 공개키 가져오기
	resp, err := http.Get("http://" + req.CpBoot + "/getPublicKey")
	if err != nil {
		http.Error(w, "failed to fetch public key", 500)
		return
	}
	defer resp.Body.Close()

	// CP 노드로부터 전송받은 공개키(PEM 형식)를 전체 읽음
	pubPem, _ := io.ReadAll(resp.Body)

	// PEM 포맷(-----BEGIN PUBLIC KEY-----)을 디코딩하여 DER 형식으로 변환
	block, _ := pem.Decode(pubPem)

	// DER 포맷을 실제 Go에서 사용 가능한 공개키 객체(interface)로 파싱
	pubIfc, _ := x509.ParsePKIXPublicKey(block.Bytes)

	// 파싱된 공개키를 ECDSA 공개키 타입으로 변환 (타입 단언)
	pubKey := pubIfc.(*ecdsa.PublicKey)

	// 메시지는 문자열 그대로 사용
	msg := []byte(req.Root + "|" + req.Ts)
	hash := sha256.Sum256(msg)

	// DER 디코딩
	sigBytes, _ := hex.DecodeString(req.Sig)

	type ecdsaSignature struct {
		R, S *big.Int
	}

	var sigStruct ecdsaSignature
	_, err = asn1.Unmarshal(sigBytes, &sigStruct)
	if err != nil {
		http.Error(w, "invalid signature format", 403)
		return
	}

	valid := ecdsa.Verify(pubKey, hash[:], sigStruct.R, sigStruct.S)

	if !valid {
		http.Error(w, "invalid signature", 403)
		log.Printf("[ANCHOR][INVALID] rejected from %s", req.CpID)
		return
	}

	// 앵커 저장
	log.Printf("[ANCHOR] Verified & adding anchor from CP Chain ... %s : %s)", req.CpID, req.Root)
	// AnchorRecord 구성 (계약 정보는 현재 비워둠)
	ar := AnchorRecord{
		CPID:             req.CpID,
		ContractSnapshot: ContractData{}, // 빈 계약 정보
		LowerRoot:        req.Root,
		AccessCatalog:    []string{}, // 비어있는 접근 리스트
		AnchorTimestamp:  req.Ts,
	}

	// pending 에 anchor 객체 전체 추가
	appendPending([]AnchorRecord{ar})
	log.Printf("[ANCHOR] Pending anchor added: %+v", ar)

	// AnchorRoot LevelDB 저장
	if err := saveAnchorToDB(req.CpID, req.Root, req.Ts); err != nil {
		log.Printf("[ANCHOR][ERROR] Failed to save anchor to DB for %s: %v", req.CpID, err)
	} else {
		log.Printf("[ANCHOR][DB] Success to save anchor to DB for %s: %v", req.CpID, err)
	}

	// 전역변수에 저장
	anchorMu.Lock()
	anchorMap[req.CpID] = AnchorInfo{Root: req.Root, Ts: req.Ts}
	anchorMu.Unlock()

	// 새로 수신한 CP 부트노드의 주소가, 기존 Cp체인의 부트노드 주소와 다른 경우
	if req.CpBoot != getCpBootAddr(req.CpID) {
		// 송신한 CP체인의 CPID와 부트노드 주소를 저장한 후 다른 ott 노드에 전파함
		log.Printf("[ANCHOR] Call broadcastNewCpBoot() for store %s : %s to CpBootMap ... )", req.CpID, req.CpBoot)
		broadcastNewCpBoot(req.CpID, req.CpBoot)
	}
	w.WriteHeader(http.StatusOK)
}

// CP가 반환하는 검색 응답 구조체
type SearchResponse struct {
	Record ContentRecord `json:"record"`
	Root   string        `json:"root"`
	Leaf   string        `json:"leaf"`
	Proof  [][2]string   `json:"proof"`
}

// CP 검색 프로세스 (핸들러에서 호출)
func handleCpSearch(cpID, keyword string) ([]byte, int, error) {

	// 1) CP 부트 주소 조회
	cpAddr := getCpBootAddr(cpID)
	if cpAddr == "" {
		fmt.Println("[Search] Invalid CP Boot Address")
		return nil, http.StatusBadGateway, nil
	}

	// 2) CP 체인에 검색 요청 (/search)
	items, err := requestCpSearch(cpAddr, keyword)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}

	// 3) OTT AnchorRoot + MerkleProof 검증
	verified, err := verifyCpResults(cpID, items)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// 4) JSON 반환
	out, _ := json.Marshal(verified)
	return out, http.StatusOK, nil
}

// CP /search 호출 (CP가 주는 JSON = []SearchResponse)
func requestCpSearch(cpAddr, keyword string) ([]SearchResponse, error) {

	url := fmt.Sprintf("http://%s/search?value=%s", cpAddr, url.QueryEscape(keyword))

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to reach CP node: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cp error: %s", string(b))
	}

	// SearchResponse 배열로 받는다
	var items []SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("invalid JSON from CP")
	}

	return items, nil
}

// OTT -> CP 검색 결과 검증
func verifyCpResults(cpID string, items []SearchResponse) ([]SearchResponse, error) {

	// 1) OTT가 저장한 최신 AnchorRoot 조회
	anchorMu.RLock()
	anch, ok := anchorMap[cpID]
	anchorMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no anchor for cp_id=%s", cpID)
	}
	anchorRoot := anch.Root

	verified := []SearchResponse{}
	// 2) 결과별 검증 수행
	for _, it := range items {

		// block root 일치 여부
		if it.Root != anchorRoot {
			continue
		}

		// Merkle 증명 검증
		if verifyMerkleProof(it.Leaf, it.Root, it.Proof) {
			verified = append(verified, it)
		}
	}

	return verified, nil
}
