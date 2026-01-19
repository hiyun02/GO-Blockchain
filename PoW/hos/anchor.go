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
// Hos(clinic Provider) 체인에서 생성되는 블록 단위 구조체
// 하나의 블록은 여러 ClinicRecord(Entries)를 포함하고,
// 그 해시들을 기반으로 Merkle Root를 계산하여 블록 헤더에 저장
////////////////////////////////////////////////////////////////////////////////

// 개인키, 공개키 자동 생성 (최초 실행 시)
func ensureKeyPair() {
	if _, ok := getMeta("meta_hos_privkey"); ok {
		return
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)

	privPem := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))
	pubPem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	putMeta("meta_hos_privkey", privPem)
	putMeta("meta_hos_pubkey", pubPem)
	log.Println("[ANCHOR][INIT] Generated private key : %s", privPem)
	log.Println("[ANCHOR][INIT] Generated public key : %s", pubPem)
	log.Println("[ANCHOR][INIT] Generated ECDSA key pair for Hos node")
}

// 공개키 조회 API (Gov가 요청할 때 사용)
// GET /getPublicKey
func getPublicKey(w http.ResponseWriter, r *http.Request) {
	pubPem, ok := getMeta("meta_hos_pubkey")
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

// Gov로 MerkleRoot 제출 (부트노드에서만 실행됨)
func submitAnchor(block LowerBlock) {
	ensureKeyPair() // 키 없으면 생성
	privPem, _ := getMeta("meta_hos_privkey")

	ts := time.Unix(time.Now().Unix(), 0).Format(time.RFC3339)
	sig := makeAnchorSignature(privPem, block.MerkleRoot, ts)

	req := map[string]any{
		"hos_id":   selfID(),
		"hos_boot": self, // ex: "hos-boot:5000"
		"root":     block.MerkleRoot,
		"ts":       ts,
		"sig":      sig,
	}

	body, _ := json.Marshal(req)
	govURL := "http://" + govBoot + "/addAnchor"
	log.Printf("[ANCHOR] Anchor Sent to Gov BOOT : %s", govBoot)
	resp, err := http.Post(govURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[ANCHOR][ERROR] failed to submit anchor: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Printf("[ANCHOR][OK] Anchor submitted to Gov (root=%s)", block.MerkleRoot[:8])
	} else {
		log.Printf("[ANCHOR][WARN] Gov rejected anchor (status=%d)", resp.StatusCode)
	}
}

// 검색 응답 구조체
type SearchResponse struct {
	Record     ClinicRecord `json:"record"`
	BlockRoot  string       `json:"block_root"`
	LatestRoot string       `json:"latest_root"`
	Leaf       string       `json:"leaf"`
	Proof      [][2]string  `json:"proof"`
}

// 쿼리 수행 함수
func searchClinic(keyword string) ([]SearchResponse, error) {
	// 키워드를 가진 블록 찾기
	blk, err := getBlockByClinicForQuery(keyword)
	if err != nil {
		return nil, err
	}

	// 블록 내부에서 레코드 매칭
	matches := findMatchesInBlock(blk, keyword)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no matching record")
	}

	// 결과 구조 생성
	results := make([]SearchResponse, 0, len(matches))
	for _, m := range matches {
		results = append(results, buildSearchResponse(m.Record, blk, m.EntryIndex))
	}

	return results, nil
}

type Match struct {
	Record     ClinicRecord
	EntryIndex int
}

// 블록 내부에서 keyword에 맞는 레코드를 찾음
func findMatchesInBlock(blk *LowerBlock, keyword string) []Match {
	matches := []Match{}

	for ei, rec := range blk.Entries {
		if rec.ClinicID == keyword {
			matches = append(matches, Match{rec, ei})
			continue
		}
		if cCode, ok := rec.Info["cCode"]; ok {
			if strings.EqualFold(fmt.Sprint(cCode), keyword) {
				matches = append(matches, Match{rec, ei})
			}
		}
	}

	return matches
}

func buildSearchResponse(rec ClinicRecord, blk *LowerBlock, entryIndex int) SearchResponse {

	// 1) 찾은 블록에서 해당 엔트리에 대한 leaf hash 꺼냄
	leaf := blk.LeafHashes[entryIndex]

	// 2) 검색된 레코드가 속한 블록을 기준으로 Merkle Proof 생성
	proof := merkleProof(blk.LeafHashes, entryIndex)

	// 3) 최종 결과 패키징
	return SearchResponse{
		Record:     rec,
		BlockRoot:  blk.MerkleRoot,  // 레코드가 존재하는 블록 루트 (블록 유효성 검증)
		LatestRoot: getLatestRoot(), // 현재 노드의 최신 블록 루트 (체인 유효성 검증)
		Leaf:       leaf,
		Proof:      proof,
	}
}

// 키워드로 블록 조회
//   - keyword가 Info(cCode 등)에 매칭되면
//     해당 포인터("bi:ei")를 통해 블록을 찾아 반환
//   - 여러 매칭이 가능할 수 있으나, 여기서는 최초 매칭 1개만 반환
func getBlockByClinicForQuery(keyword string) (*LowerBlock, error) {

	// Info(cCode 등) 색인 조회 (소문자 normalize)
	if v, err := db.Get([]byte("info_cCode_"+strings.ToLower(keyword)), nil); err == nil {
		if bi, _, ok := parsePtr(string(v)); ok {
			return getBlockByIndexForPointer(bi)
		}
	}

	return nil, fmt.Errorf("no block found for keyword: %s", keyword)
}

func getBlockByIndexForPointer(index int) (*LowerBlock, error) {
	key := fmt.Sprintf("block_%d", index)

	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return nil, fmt.Errorf("block_%d not found: %w", index, err)
	}

	var block LowerBlock
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, fmt.Errorf("failed to decode block_%d: %w", index, err)
	}

	return &block, nil
}
