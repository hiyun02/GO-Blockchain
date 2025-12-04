package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// SHA-256 해시를 hex 문자열로 반환
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// JSON을 key 정렬 후 직렬화 (해시 재현성 확보)
func jsonCanonical(obj interface{}) []byte {
	m, _ := json.Marshal(obj)
	var temp map[string]interface{}
	json.Unmarshal(m, &temp)

	keys := make([]string, 0, len(temp))
	for k := range temp {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make(map[string]interface{})
	for _, k := range keys {
		ordered[k] = temp[k]
	}

	// Compact JSON (no spaces, no HTML escaping)
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "")
	enc.Encode(ordered)
	out := bytes.TrimSpace(buf.Bytes())

	return out
}

// raw bytes 기반 표준 방식
func merkleRootHex(leaves []string) string {
	if len(leaves) == 0 {
		return ""
	}
	// leaf들을 raw byte로 decode한 배열로 변환
	var level [][]byte
	for _, h := range leaves {
		b, _ := hex.DecodeString(h)
		level = append(level, b)
	}

	// 노드가 하나 남을 때까지 결합
	for len(level) > 1 {
		var next [][]byte

		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				// left + right
				combined := append(level[i], level[i+1]...)
				sum := sha256.Sum256(combined)
				next = append(next, sum[:])
			} else {
				// odd → duplicate
				combined := append(level[i], level[i]...)
				sum := sha256.Sum256(combined)
				next = append(next, sum[:])
			}
		}

		level = next
	}

	return hex.EncodeToString(level[0])
}

// Merkle Proof 검증 : O(logN)
func verifyMerkleProof(leafHex string, rootHex string, proof [][2]string) bool {
	h, _ := hex.DecodeString(leafHex)
	for _, p := range proof {
		sib, _ := hex.DecodeString(p[0])
		pos := p[1]
		if pos == "L" {
			sum := sha256.Sum256(append(sib, h...))
			h = sum[:]
		} else {
			sum := sha256.Sum256(append(h, sib...))
			h = sum[:]
		}
	}
	return hex.EncodeToString(h) == rootHex
}

// ContentRecord 해시 생성 => CP 체인에서의 무결성 검증
func hashContentRecord(rec ContentRecord) string {
	canonical := jsonCanonical(rec)
	return sha256Hex(canonical)
}

// 표준 방식 raw bytes 기반
// leafHashes = hex 인코딩된 leaf hash 문자열 배열
// idx = 검색된 Leaf의 index
func merkleProof(leafHashes []string, idx int) [][2]string {
	if idx < 0 || idx >= len(leafHashes) {
		return nil
	}

	// 1) leaf hex들을 raw byte로 decode하여 level 구성
	var level [][]byte
	for _, h := range leafHashes {
		b, _ := hex.DecodeString(h)
		level = append(level, b)
	}

	current := idx
	var proof [][2]string

	// 2) sibling들을 따라 올라가며 증명 생성
	for len(level) > 1 {
		var next [][]byte

		for i := 0; i < len(level); i += 2 {
			var parent []byte
			if i+1 < len(level) {
				combined := append(level[i], level[i+1]...)
				sum := sha256.Sum256(combined)
				parent = sum[:]
			} else {
				combined := append(level[i], level[i]...)
				sum := sha256.Sum256(combined)
				parent = sum[:]
			}
			next = append(next, parent)
		}

		// 현재 index의 sibling 찾기
		siblingIdx := current ^ 1
		if siblingIdx < len(level) {
			sibHex := hex.EncodeToString(level[siblingIdx])
			if current%2 == 0 {
				proof = append(proof, [2]string{sibHex, "R"})
			} else {
				proof = append(proof, [2]string{sibHex, "L"})
			}
		}

		current = current / 2
		level = next
	}

	return proof
}

// 여러 CP 레코드 속 Merkle Root를 병합하여 상위 MerkleRoot 계산
func computeUpperMerkleRoot(records []AnchorRecord) string {
	if len(records) == 0 {
		return ""
	}
	leaf := make([]string, len(records))
	for i, rec := range records {
		leaf[i] = rec.LowerRoot // CP 체인 루트 기반으로 상위 루트 계산
	}
	return merkleRootHex(leaf)
}
