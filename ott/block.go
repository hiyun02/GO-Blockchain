package main

import (
	"log"
	"strings"
	"time"
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
	Elapsed    int64          `json:"elapsed"`     // 채굴 소요 시간
}

// 제네시스 블록 생성
func mineGenesisBlock(ottID string) UpperBlock {
	log.Printf("[PoW] Mining genesis block...")
	mineStart := time.Now()
	// 제네시스는 엔트리 없음, merkleRoot는 sha256("")
	merkleRoot := sha256Hex([]byte{})
	prevHash := strings.Repeat("0", 64)
	timestamp := "2025-11-26T01:07:18Z"
	index := 0

	header := PoWHeader{
		Index:      index,
		PrevHash:   prevHash,
		MerkleRoot: merkleRoot,
		Timestamp:  timestamp,
		Difficulty: GlobalDifficulty,
	}

	// === 제네시스 Nonce 탐색 ===
	nonce := 0
	var hash string

	for {
		header.Nonce = nonce
		hash = computeHashForPoW(header)
		if validHash(hash, GlobalDifficulty) {
			log.Printf("[PoW] GENESIS mined: nonce=%d hash=%s", nonce, hash)
			break
		}
		nonce++
	}
	mineEnd := time.Now()
	elapsed := int64(mineEnd.Sub(mineStart).Seconds())
	// === UpperBlock으로 변환 ===
	genesis := UpperBlock{
		Index:      index,
		OttID:      ottID,
		PrevHash:   prevHash,
		Timestamp:  header.Timestamp,
		Records:    []AnchorRecord{}, // Genesis는 Records 없음
		MerkleRoot: merkleRoot,
		Nonce:      header.Nonce,
		Difficulty: GlobalDifficulty,
		BlockHash:  hash,
		Elapsed:    elapsed,
	}
	// 난이도 조정 수행
	adjustDifficulty(0, elapsed)
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
	return sha256Hex(jsonCanonical(hdr))
}
