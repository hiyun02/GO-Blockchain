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
	"log"
	"net/http"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// Anchor
// ------------------------------------------------------------
// CP(Content Provider) 체인에서 생성되는 블록 단위 구조체
// 하나의 블록은 여러 ContentRecord(Entries)를 포함하고,
// 그 해시들을 기반으로 Merkle Root를 계산하여 블록 헤더에 저장
////////////////////////////////////////////////////////////////////////////////

// 개인키, 공개키 자동 생성 (최초 실행 시)
func ensureKeyPair() {
	if _, ok := getMeta("meta_cp_privkey"); ok {
		return
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)

	privPem := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))
	pubPem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	putMeta("meta_cp_privkey", privPem)
	putMeta("meta_cp_pubkey", pubPem)
	log.Println("[ANCHOR][INIT] Generated private key : %s", privPem)
	log.Println("[ANCHOR][INIT] Generated public key : %s", pubPem)
	log.Println("[ANCHOR][INIT] Generated ECDSA key pair for CP node")
}

// 공개키 조회 API (OTT가 요청할 때 사용)
// GET /getPublicKey
func getPublicKey(w http.ResponseWriter, r *http.Request) {
	pubPem, ok := getMeta("meta_cp_pubkey")
	if !ok {
		http.Error(w, "public key not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write([]byte(pubPem))
}

// 앵커 서명 생성 (ECDSA)
func makeAnchorSignature(privPem string, root string, ts string) string {
	block, _ := pem.Decode([]byte(privPem))
	priv, _ := x509.ParseECPrivateKey(block.Bytes)

	msg := []byte(fmt.Sprintf("%s|%d", root, ts))
	hash := sha256.Sum256(msg)

	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
	sig := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(sig)
}

// OTT로 MerkleRoot 제출 (부트노드에서만 실행됨)
func submitAnchor(block LowerBlock) {
	ensureKeyPair() // 키 없으면 생성
	privPem, _ := getMeta("meta_cp_privkey")

	ts := time.Unix(time.Now().Unix(), 0).Format(time.RFC3339)
	sig := makeAnchorSignature(privPem, block.MerkleRoot, ts)

	req := map[string]any{
		"cp_id":   selfID(),
		"cp_boot": self, // ex: "cp-boot:5000"
		"root":    block.MerkleRoot,
		"ts":      ts,
		"sig":     sig,
	}

	body, _ := json.Marshal(req)
	ottURL := "http://" + ottBoot + "/addAnchor"
	log.Printf("[ANCHOR] Anchor Sent to OTT BOOT : %s", ottBoot)
	resp, err := http.Post(ottURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[ANCHOR][ERROR] failed to submit anchor: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Printf("[ANCHOR][OK] Anchor submitted to OTT (root=%s)", block.MerkleRoot[:8])
	} else {
		log.Printf("[ANCHOR][WARN] OTT rejected anchor (status=%d)", resp.StatusCode)
	}
}
