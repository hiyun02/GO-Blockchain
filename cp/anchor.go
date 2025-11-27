package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
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

	// 메시지는 문자열 그대로 사용
	msg := []byte(root + "|" + ts)
	hash := sha256.Sum256(msg)

	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])

	// DER 인코딩(ECDSA 표준)
	type ecdsaSignature struct {
		R, S *big.Int
	}
	der, _ := asn1.Marshal(ecdsaSignature{R: r, S: s})

	return hex.EncodeToString(der)
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
func searchContent(keyword string) ([]map[string]any, error) {
	// 키워드를 가진 블록 찾기
	blk, err := getBlockByContent(keyword)
	if err != nil {
		return nil, err
	}

	// 블록 내부에서 레코드 매칭
	matches := findMatchesInBlock(blk, keyword)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no matching record")
	}

	// 결과 구조 생성
	results := []map[string]any{}
	for _, m := range matches {
		results = append(results, buildSearchResult(m.Record, blk, m.EntryIndex))
	}

	return results, nil
}

type Match struct {
	Record     ContentRecord
	EntryIndex int
}

// ------------------------------------------
// 블록 내부에서 keyword에 맞는 레코드를 찾음
// ------------------------------------------
func findMatchesInBlock(blk LowerBlock, keyword string) []Match {
	matches := []Match{}

	for ei, rec := range blk.Entries {
		if rec.ContentID == keyword {
			matches = append(matches, Match{rec, ei})
			continue
		}
		if rec.Fingerprint == keyword {
			matches = append(matches, Match{rec, ei})
			continue
		}
		if title, ok := rec.Info["title"]; ok {
			if strings.EqualFold(fmt.Sprint(title), keyword) {
				matches = append(matches, Match{rec, ei})
			}
		}
	}

	return matches
}

func buildSearchResult(rec ContentRecord, blk LowerBlock, entryIndex int) map[string]any {

	// 1) leaf hash = ContentRecord 해시
	leaf := hashContentRecord(rec)

	// 2) 블록 전체 leaf hash 배열 생성
	leafHashes := make([]string, len(blk.Entries))
	for i, e := range blk.Entries {
		leafHashes[i] = hashContentRecord(e)
	}

	// 3) Merkle Proof 생성
	proof := merkleProof(leafHashes, entryIndex)

	// 4) 최종 결과 패키징
	return map[string]any{
		"record": rec,
		"root":   blk.MerkleRoot, // 블록 생성 시 이미 merkleRootHex 적용됨
		"leaf":   leaf,
		"proof":  proof, // [][]string{"sib","L/R"}
	}
}
