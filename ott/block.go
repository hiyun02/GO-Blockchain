package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

////////////////////////////////////////////////////////////////////////////////
// UpperBlock (OTT 체인 블록 구조)
// ------------------------------------------------------------
// CP 체인으로부터 전달받은 서명된 MerkleRoot를 수집하여 하나의 상위 블록으로 요약함
// 각 UpperBlock은 CP 루트들의 루트(MerkleRoot of roots)를 포함
////////////////////////////////////////////////////////////////////////////////

// OTT 체인의 블록 구조체
// --------------------------------------------------
// - 하나의 UpperBlock은 여러 CP 체인들의 루트(anchor)를 포함
type UpperBlock struct {
	Index      int            `json:"index"`       // 블록 번호
	OttID      string         `json:"ott_id"`      // OTT 체인 식별자
	PrevHash   string         `json:"prev_hash"`   // 이전 블록의 해시
	Timestamp  string         `json:"timestamp"`   // 생성 시간 (RFC3339 형식)
	Records    []AnchorRecord `json:"records"`     // CP 체인에서 제출한 AnchorRecord 목록
	MerkleRoot string         `json:"merkle_root"` // AnchorRecords 속 MerkleRoot들을 병합하여 계산한 상위 MerkleRoot
	Nonce      int            `json:"nonce"`       // PoW용 Nonce
	Difficulty int            `json:"difficulty"`  // 난이도
	BlockHash  string         `json:"block_hash"`  // 블록 전체 해시
}

// 제네시스 상수
const (
	genesisTimestamp = "1980-01-01T00:00:00Z"                                             // 재현성 보장
	prevHashZeros    = "0000000000000000000000000000000000000000000000000000000000000000" // 64자리 0
)

// 제네시스 블록 생성
func createGenesisBlock(ottID string) UpperBlock {
	root := sha256Hex([]byte{}) // 빈 MerkleRoot
	genesis := UpperBlock{
		Index:      0,
		OttID:      ottID,
		PrevHash:   prevHashZeros,
		Timestamp:  genesisTimestamp,
		Records:    []AnchorRecord{},
		MerkleRoot: root,
		Nonce:      0,
		Difficulty: 0,
	}
	genesis.BlockHash = genesis.computeHash()
	return genesis
}

// UpperBlock 해시 계산 (헤더 서브셋 기준)
// ------------------------------------------------------------
// - 포함: Index, OttID, PrevHash, Timestamp, MerkleRoot, Nonce, Difficulty
// - 제외: Records, BlockHash (자가참조 및 가변 데이터 배제)
func (b UpperBlock) computeHash() string {
	hdr := struct {
		Index      int    `json:"index"`
		OttID      string `json:"ott_id"`
		PrevHash   string `json:"prev_hash"`
		Timestamp  string `json:"timestamp"`
		MerkleRoot string `json:"merkle_root"`
		Nonce      int    `json:"nonce"`
		Difficulty int    `json:"difficulty"`
	}{
		Index:      b.Index,
		OttID:      b.OttID,
		PrevHash:   b.PrevHash,
		Timestamp:  b.Timestamp,
		MerkleRoot: b.MerkleRoot,
		Nonce:      b.Nonce,
		Difficulty: b.Difficulty,
	}

	data, _ := json.Marshal(hdr)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
