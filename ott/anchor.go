package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

// OTT에서 CP가 제출한 앵커를 수신하고 검증한 후 pending 추가함수 호출(부트노드만 수행)
func addAnchor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CpID   string `json:"cp_id"`
		CpBoot string `json:"cp_boot"`
		Root   string `json:"root"`
		Ts     int64  `json:"ts"`
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

	// 서명 검증 과정 시작(ECDSA.Verify)
	// CP가 서명한 원문 메시지 구성
	msg := []byte(fmt.Sprintf("%s|%d", req.Root, req.Ts))

	// 메시지를 SHA-256으로 해시 (서명은 해시값에 대해 수행됨)
	hash := sha256.Sum256(msg)

	// CP로부터 전달받은 서명(hex 문자열)을 바이트 배열로 디코딩
	sigBytes, _ := hex.DecodeString(req.Sig)

	// ECDSA 서명은 (r, s) 두 부분으로 나뉘므로 반으로 분할
	half := len(sigBytes) / 2
	rBytes := sigBytes[:half]
	sBytes := sigBytes[half:]

	// 각각 big.Int 타입으로 변환하여 서명 파라미터 구성
	sigR := new(big.Int).SetBytes(rBytes)
	sigS := new(big.Int).SetBytes(sBytes)

	// 공개키(pubKey)로 해시(hash[:])와 서명(r,s)을 검증
	// 유효하면 true 반환 => 정상 서명 (CP가 실제 서명한 것)
	valid := ecdsa.Verify(pubKey, hash[:], sigR, sigS)

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
		AnchorTimestamp:  time.Unix(req.Ts, 0).Format(time.RFC3339),
	}

	// pendingAnchors 에 anchor 객체 전체 추가
	ch.appendAnchorToPending(ar)

	log.Printf("[ANCHOR] Pending anchor added: %+v", ar)

	// 송신한 CP체인의 CPID와 부트노드 주소를 저장한 후 다른 ott 노드에 전파함
	log.Printf("[ANCHOR] Call broadcastNewCpBoot() for store %s : %s to CpBootMap ... )", req.CpID, req.CpBoot)
	broadcastNewCpBoot(req.CpID, req.CpBoot)
	w.WriteHeader(http.StatusOK)
}
