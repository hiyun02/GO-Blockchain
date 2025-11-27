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

	// 송신한 CP체인의 CPID와 부트노드 주소를 저장한 후 다른 ott 노드에 전파함
	log.Printf("[ANCHOR] Call broadcastNewCpBoot() for store %s : %s to CpBootMap ... )", req.CpID, req.CpBoot)
	broadcastNewCpBoot(req.CpID, req.CpBoot)
	w.WriteHeader(http.StatusOK)
}

// CP 검색 프로세스 (핸들러에서 호출)
func handleCpSearch(cpID, keyword string) ([]byte, int, error) {

	// 1) CP 부트 주소 조회
	cpAddr := getCpBootAddr(cpID)
	if cpAddr == "" {
		fmt.Println("[Anchor] Invalid CP Boot Address")
		return nil, http.StatusBadGateway, nil
	}

	// 2) CP 체인에 검색 요청 (/search)
	items, err := requestCpSearch(cpAddr, keyword)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}

	//// 3) OTT가 AnchorRoot + MerkleProof 검증
	//verified, err := verifyCpResults(cpID, items)
	//if err != nil {
	//	return nil, http.StatusInternalServerError, err
	//}

	// 4) JSON 반환
	out, _ := json.Marshal(items)
	return out, http.StatusOK, nil
}

// CP /search 호출 (record+root+leaf+proof)
func requestCpSearch(cpAddr, keyword string) ([]map[string]any, error) {

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

	var items []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("invalid JSON from CP")
	}

	return items, nil
}

//
//// OTT -> CP 결과 검증 (AnchorRoot + MerkleProof)
//func verifyCpResults(cpID string, items []map[string]any) ([]map[string]any, error) {
//
//	// 1) AnchorRoot 조회
//	anchorMu.RLock()
//	anch, ok := anchorMap[cpID]
//	anchorMu.RUnlock()
//
//	if !ok {
//		return nil, fmt.Errorf("no anchor for cp_id=%s", cpID)
//	}
//	anchorRoot := anch.Root
//
//	verified := []map[string]any{}
//
//	// 2) 결과별 검증 수행
//	for _, it := range items {
//
//		// (1) block root 일치 여부
//		blockRoot, ok := it["root"].(string)
//		if !ok || blockRoot != anchorRoot {
//			continue
//		}
//
//		// (2) leaf hash
//		leaf, _ := it["leaf"].(string)
//
//		// (3) proof 파싱
//		rawProof, _ := it["proof"].([]any)
//		proof := parseProof(rawProof)
//
//		// (4) Merkle 증명 검증
//		if verifyMerkleProof(leaf, blockRoot, proof) {
//			verified = append(verified, it)
//		}
//	}
//
//	return verified, nil
//}

// CP가 보낸 proof(JSON 배열) => [][2]string 로 변환
func parseProof(arr []any) [][2]string {
	proof := make([][2]string, 0)
	for _, v := range arr {
		p, ok := v.([]any)
		if !ok || len(p) != 2 {
			continue
		}
		sib, _ := p[0].(string)
		pos, _ := p[1].(string)
		proof = append(proof, [2]string{sib, pos})
	}
	return proof
}
