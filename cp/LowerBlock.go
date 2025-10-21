package main

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
	CpID       string          `json:"cp_id"`       // CP 체인 식별자
	PrevHash   string          `json:"prev_hash"`   // 이전 블록의 해시
	Timestamp  string          `json:"timestamp"`   // 생성 시간 (RFC3339 형식)
	Entries    []ContentRecord `json:"entries"`     // 블록 내 콘텐츠 목록
	MerkleRoot string          `json:"merkle_root"` // Entries의 해시 기반 머클루트
	BlockHash  string          `json:"block_hash"`  // 블록 전체 해시 (헤더 기준)
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
	}
	genesis.BlockHash = genesis.computeHash()
	return genesis
}

// 해시에 들어갈 필드 서브셋만 직렬화하여 블록 해시 계산
func (b LowerBlock) computeHash() string {
	hdr := struct {
		Index      int    `json:"index"`
		CpID       string `json:"cp_id"`
		PrevHash   string `json:"prev_hash"`
		Timestamp  string `json:"timestamp"`
		MerkleRoot string `json:"merkle_root"`
	}{
		Index: b.Index, CpID: b.CpID, PrevHash: b.PrevHash,
		Timestamp: b.Timestamp, MerkleRoot: b.MerkleRoot,
	}
	return sha256Hex(jsonCanonical(hdr))
}
