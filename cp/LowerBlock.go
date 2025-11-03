package main

import "time"

////////////////////////////////////////////////////////////////////////////////
// LowerBlock (CP 체인 블록 구조)
// ------------------------------------------------------------
// CP(Content Provider) 체인에서 생성되는 블록 단위 구조체
// 하나의 블록은 여러 ContentRecord(Entries)를 포함하고,
// 그 해시들을 기반으로 Merkle Root를 계산하여 블록 헤더에 저장
////////////////////////////////////////////////////////////////////////////////

// LowerBlock : CP 체인에서 사용하는 블록 구조체
// --------------------------------------------------
// - 하나의 블록은 여러 개의 ContentRecord(entries)를 포함
// - PBFT 기반이므로 PoW 없음 (확정형 체인)
// - MerkleRoot는 블록 내 콘텐츠 무결성 보장을 위해 계산됨
type LowerBlock struct {
	Index      int             `json:"index"`       // 블록 번호
	CpID       string          `json:"cp_id"`       // 체인 식별자
	PrevHash   string          `json:"prev_hash"`   // 이전 블록 해시
	Timestamp  string          `json:"timestamp"`   // 생성 시간 (RFC3339)
	Entries    []ContentRecord `json:"entries"`     // 블록 내 콘텐츠 목록
	MerkleRoot string          `json:"merkle_root"` // Entries 해시 기반 Merkle Root
	Nonce      int             `json:"nonce"`       // 작업증명에서 찾은 nonce 값
	Difficulty int             `json:"difficulty"`  // 난이도 (ex: 4 => 0000)
	BlockHash  string          `json:"block_hash"`  // 최종 블록 해시
}

// 제네시스 상수
const (
	genesisTimestamp = "1970-01-01T00:00:00Z"                                             // 재현성 보장
	prevHashZeros    = "0000000000000000000000000000000000000000000000000000000000000000" // 64자리 0
)

// 제네시스 블록 생성
func createGenesisBlock(cpID string) LowerBlock {
	emptyRoot := sha256Hex([]byte{})
	genesis := LowerBlock{
		Index:      0,
		CpID:       cpID,
		PrevHash:   prevHashZeros,
		Timestamp:  genesisTimestamp,
		Entries:    []ContentRecord{},
		MerkleRoot: emptyRoot,
		Nonce:      0,
		Difficulty: 0,
	}
	genesis.BlockHash = genesis.computeHash()
	return genesis
}

// 블록 헤더 기준 해시 계산 (PoW용)
func (b LowerBlock) hashForPoW() string {
	hdr := struct {
		Index      int    `json:"index"`
		CpID       string `json:"cp_id"`
		PrevHash   string `json:"prev_hash"`
		Timestamp  string `json:"timestamp"`
		MerkleRoot string `json:"merkle_root"`
		Nonce      int    `json:"nonce"`
		Difficulty int    `json:"difficulty"`
	}{
		Index:      b.Index,
		CpID:       b.CpID,
		PrevHash:   b.PrevHash,
		Timestamp:  b.Timestamp,
		MerkleRoot: b.MerkleRoot,
		Nonce:      b.Nonce,
		Difficulty: b.Difficulty,
	}
	return sha256Hex(jsonCanonical(hdr))
}

// 새 블록 생성 (mineBlock 결과 반영)
func createNewBlock(cpID string, prev LowerBlock, entries []ContentRecord, difficulty int) LowerBlock {
	// 각 콘텐츠 해싱 후 Merkle Root 계산
	leafHashes := make([]string, len(entries))
	for i, r := range entries {
		leafHashes[i] = hashContentRecord(r)
	}
	root := merkleRootHex(leafHashes)
	index := prev.Index + 1
	ts := time.Now().Format(time.RFC3339)

	// PoW 수행
	result := mineBlock(prev.BlockHash, root, index, difficulty)

	return LowerBlock{
		Index:      index,
		CpID:       cpID,
		PrevHash:   prev.BlockHash,
		Timestamp:  ts,
		Entries:    entries,
		MerkleRoot: root,
		Nonce:      result.Nonce,
		Difficulty: difficulty,
		BlockHash:  result.BlockHash,
	}
}
