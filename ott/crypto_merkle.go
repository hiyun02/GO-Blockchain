package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// SHA-256 해시를 hex 문자열로 반환
func Sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// JSON을 key 정렬 후 직렬화 (해시 재현성 확보)
func JsonCanonical(obj interface{}) []byte {
	m, _ := json.Marshal(obj)
	var temp map[string]interface{}
	json.Unmarshal(m, &temp)

	// key 정렬
	keys := make([]string, 0, len(temp))
	for k := range temp {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make(map[string]interface{})
	for _, k := range keys {
		ordered[k] = temp[k]
	}

	result, _ := json.Marshal(ordered)
	return result
}

// Merkle Root 계산 : O(N)
func MerkleRootHex(leafHashes []string) string {
	if len(leafHashes) == 0 {
		return ""
	}
	nodes := leafHashes
	for len(nodes) > 1 {
		var newLevel []string
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				combined := append([]byte(nodes[i]), []byte(nodes[i+1])...)
				newLevel = append(newLevel, Sha256Hex(combined))
			} else {
				// 홀수일 때 마지막 노드 복제
				combined := append([]byte(nodes[i]), []byte(nodes[i])...)
				newLevel = append(newLevel, Sha256Hex(combined))
			}
		}
		nodes = newLevel
	}
	return nodes[0]
}

// Merkle Proof 검증 : O(logN)
func VerifyMerkleProof(leafHex string, rootHex string, proof [][2]string) bool {
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
func HashContentRecord(rec ContentRecord) string {
	canonical := JsonCanonical(rec)
	return Sha256Hex(canonical)
}

// Merkle Proof 생성 (리프 인덱스 => 경로)
// proof = [ (형제해시, "L"/"R") , ... ]
func MerkleProof(leafHashes []string, idx int) [][2]string {
	if idx < 0 || idx >= len(leafHashes) {
		return nil
	}
	var proof [][2]string
	nodes := leafHashes

	current := idx
	for len(nodes) > 1 {
		var nextLevel []string
		for i := 0; i < len(nodes); i += 2 {
			var parent string
			if i+1 < len(nodes) {
				combined := append([]byte(nodes[i]), []byte(nodes[i+1])...)
				parent = Sha256Hex(combined)
			} else {
				combined := append([]byte(nodes[i]), []byte(nodes[i])...)
				parent = Sha256Hex(combined)
			}
			nextLevel = append(nextLevel, parent)
		}

		// 형제 노드 계산
		siblingIdx := current ^ 1 // 0=>1, 1=>0 패턴
		if siblingIdx < len(nodes) {
			sibling := nodes[siblingIdx]
			if current%2 == 0 {
				proof = append(proof, [2]string{sibling, "R"})
			} else {
				proof = append(proof, [2]string{sibling, "L"})
			}
		}
		current = current / 2
		nodes = nextLevel
	}
	return proof
}
