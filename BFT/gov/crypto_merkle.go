package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ----------------------------------------------------------------------
// SHA256 헬퍼
// ----------------------------------------------------------------------
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
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

// ClinicRecord 해시 생성 -> Hos 체인에서의 무결성 검증
func hashClinicRecord(rec ClinicRecord) string {
	canonical := jsonCanonical(rec)
	return sha256Hex(canonical)
}

// ----------------------------------------------------------------------
// 두 해시의 부모 해시 계산 (left + right 바이트 결합 후 SHA256)
// Hos/Gov 모두 이 방식만 사용해야 한다
// ----------------------------------------------------------------------
func pairHash(left, right string) string {
	// hex 문자열 → raw bytes
	lb, _ := hex.DecodeString(left)
	rb, _ := hex.DecodeString(right)

	// 바이트 단위로 정확히 이어붙이기
	merged := append(lb, rb...)
	return sha256Hex(merged)
}

// ----------------------------------------------------------------------
// Merkle Root 계산
// leaves: hex 문자열 배열 (leaf hash들)
// ----------------------------------------------------------------------
func merkleRootHex(leaves []string) string {
	n := len(leaves)
	if n == 0 {
		return sha256Hex([]byte{}) // 빈 경우도 SHA256("")으로 통일
	}
	if n == 1 {
		return leaves[0]
	}

	// 현재 레벨
	level := make([]string, n)
	copy(level, leaves)

	// 레벨 단위로 반복
	for len(level) > 1 {
		// 홀수면 마지막 요소 복제
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}

		var newLevel []string
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := level[i+1]
			parent := pairHash(left, right)
			newLevel = append(newLevel, parent)
		}
		level = newLevel
	}

	return level[0]
}

// ----------------------------------------------------------------------
// Merkle Proof 생성
// proof = [][2]string { direction, sibling }
// direction = "L" 또는 "R"
// ----------------------------------------------------------------------
func merkleProof(leaves []string, index int) [][2]string {
	n := len(leaves)
	if index < 0 || index >= n {
		return nil
	}

	// 레벨 복사
	level := make([]string, n)
	copy(level, leaves)

	proof := make([][2]string, 0)

	curIndex := index

	// 루트에 도달할 때까지
	for len(level) > 1 {

		// 홀수 leaf padding
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}

		// 현재 레벨에서 sibling 구하기
		var siblingIndex int
		if curIndex%2 == 0 {
			// 오른쪽 형제가 존재
			siblingIndex = curIndex + 1
			proof = append(proof, [2]string{"R", level[siblingIndex]})
		} else {
			// 왼쪽 형제
			siblingIndex = curIndex - 1
			proof = append(proof, [2]string{"L", level[siblingIndex]})
		}

		// 다음 레벨로 이동
		var newLevel []string
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := level[i+1]
			parent := pairHash(left, right)
			newLevel = append(newLevel, parent)
		}

		level = newLevel
		curIndex = curIndex / 2
	}

	return proof
}

// ----------------------------------------------------------------------
// Merkle Proof 검증
// direction = "L" -> sibling이 왼쪽
// direction = "R" -> sibling이 오른쪽
// ----------------------------------------------------------------------
func verifyMerkleProof(leaf string, proof [][2]string, root string) bool {
	computed := leaf

	for _, p := range proof {
		dir := p[0]
		sib := p[1]

		if dir == "L" {
			computed = pairHash(sib, computed)
		} else {
			computed = pairHash(computed, sib)
		}
	}

	return computed == root
}

// 여러 Hos 레코드 속 Merkle Root를 병합하여 상위 MerkleRoot 계산
func computeUpperMerkleRoot(records []AnchorRecord) string {
	if len(records) == 0 {
		return ""
	}
	leaf := make([]string, len(records))
	for i, rec := range records {
		leaf[i] = rec.LowerRoot // Hos 체인 루트 기반으로 상위 루트 계산
	}
	return merkleRootHex(leaf)
}
