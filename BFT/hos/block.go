package main

import (
	"log"
	"strings"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// LowerBlock (Hos 체인 블록 구조)
// ------------------------------------------------------------
// Hos(Clinic Provider) 체인에서 생성되는 블록 단위 구조체
// 하나의 블록은 여러 ClinicRecord(Entries)를 포함하고,
// 그 해시들을 기반으로 Merkle Root를 계산하여 블록 헤더에 저장
////////////////////////////////////////////////////////////////////////////////

// LowerBlock : Hos 체인에서 사용하는 블록 구조체
// --------------------------------------------------
// - 하나의 블록은 여러 개의 ClinicRecord(entries)를 포함
// - MerkleRoot는 블록 내 진료 정보 무결성 보장을 위해 계산됨
type LowerBlock struct {
	Index      int            `json:"index"`       // 블록 번호
	HosID      string         `json:"hos_id"`      // Hos 체인 식별자
	PrevHash   string         `json:"prev_hash"`   // 이전 블록의 해시
	Timestamp  string         `json:"timestamp"`   // 생성 시간 (RFC3339 형식)
	Entries    []ClinicRecord `json:"entries"`     // 블록 내 진료 정보 목록
	MerkleRoot string         `json:"merkle_root"` // Entries의 해시 기반 머클루트
	Nonce      int            `json:"nonce"`       // PoW 성공 시점의 Nonce
	Difficulty int            `json:"difficulty"`  // 난이도 (ex: 4 => "0000"으로 시작)
	BlockHash  string         `json:"block_hash"`  // 블록 전체 해시 (헤더 기준)
	Elapsed    float32        `json:"elapsed"`     // 채굴 소요 시간
	LeafHashes []string       `json:"leaf_hashes"` // Merkle Proof 재현을 위한 해시값 모음
}

// 제네시스 블록 생성
func mineGenesisBlock(hosID string) LowerBlock {
	log.Printf("[PoW] Mining genesis block...")
	mineStart := time.Now()
	// 제네시스는 엔트리 없음
	merkleRoot := ""
	prevHash := strings.Repeat("0", 64)
	timestamp := "2025-11-28T01:07:18Z"
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
	elapsed := float32(mineEnd.Sub(mineStart).Seconds())
	// === LowerBlock으로 변환 ===
	genesis := LowerBlock{
		Index:      index,
		HosID:      hosID,
		PrevHash:   prevHash,
		Timestamp:  header.Timestamp,
		Entries:    []ClinicRecord{}, // Genesis는 Entry 없음
		MerkleRoot: merkleRoot,
		Nonce:      header.Nonce,
		Difficulty: GlobalDifficulty,
		BlockHash:  hash,
		Elapsed:    elapsed,
		LeafHashes: []string{},
	}
	// 난이도 조정 수행
	adjustDifficulty(0, elapsed)
	return genesis
}

// 블록 헤더 기준 해시 계산
func (b LowerBlock) computeHash() string {
	hdr := struct {
		Index      int    `json:"index"`
		HosID      string `json:"hos_id"`
		PrevHash   string `json:"prev_hash"`
		Timestamp  string `json:"timestamp"`
		MerkleRoot string `json:"merkle_root"`
		Nonce      int    `json:"nonce"`
		Difficulty int    `json:"difficulty"`
	}{
		Index:      b.Index,
		HosID:      b.HosID,
		PrevHash:   b.PrevHash,
		Timestamp:  b.Timestamp,
		MerkleRoot: b.MerkleRoot,
		Nonce:      b.Nonce,
		Difficulty: b.Difficulty,
	}
	return sha256Hex(jsonCanonical(hdr))
}
