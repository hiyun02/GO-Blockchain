package main

import (
	"log"
	"strings"
)

// //////////////////////////////////////////////////////////////////////////////
// LowerBlock (Hos 체인 블록 구조)
// ------------------------------------------------------------
// Hos(Clinic Provider) 체인에서 생성되는 블록 단위 구조체
// 하나의 블록은 여러 ClinicRecord(Entries)를 포함하고,
// 그 해시들을 기반으로 Merkle Root를 계산하여 블록 헤더에 저장
// //////////////////////////////////////////////////////////////////////////////
type LowerBlock struct {
	Index      int            `json:"index"`       // 블록 번호
	HosID      string         `json:"hos_id"`      // Hos 체인 식별자
	PrevHash   string         `json:"prev_hash"`   // 이전 블록의 해시
	Timestamp  string         `json:"timestamp"`   // 생성 시간 (RFC3339 형식)
	Entries    []ClinicRecord `json:"entries"`     // 블록 내 진료 정보 목록
	MerkleRoot string         `json:"merkle_root"` // Entries의 해시 기반 머클루트
	Proposer   string         `json:"proposer"`    // 해당 블록의 합의 집행자
	Signatures []string       `json:"signatures"`  // 2f+1개 이상의 노드 서명 목록 (합의 증거)
	BlockHash  string         `json:"block_hash"`  // 블록 전체 해시 (헤더 기준)
	Elapsed    float32        `json:"elapsed"`     // 소요 시간
	LeafHashes []string       `json:"leaf_hashes"` // Merkle Proof 재현을 위한 해시값 모음
}

// 제네시스 블록 생성
func createGenesisBlock(hosID string) LowerBlock {
	log.Printf("[Blk] Start genesis block...")
	genesis := LowerBlock{
		Index:      0,
		HosID:      hosID,
		PrevHash:   strings.Repeat("0", 64),
		Timestamp:  "2026-01-21 T01:07:18Z",
		Entries:    []ClinicRecord{},
		MerkleRoot: "",
		Proposer:   "SYSTEM",   // 제네시스는 시스템에 의해 생성됨
		Signatures: []string{}, // 제네시스는 투표 절차 생략
		Elapsed:    0,
		LeafHashes: []string{},
	}
	genesis.BlockHash = genesis.computeHash()
	log.Printf("[Blk] Start genesis block...")
	return genesis
}

// 블록의 식별자인 Hash 값 계산
func (b LowerBlock) computeHash() string {
	hdr := struct {
		Index      int    `json:"index"`
		HosID      string `json:"hos_id"`
		PrevHash   string `json:"prev_hash"`
		Timestamp  string `json:"timestamp"`
		MerkleRoot string `json:"merkle_root"`
		Proposer   string `json:"proposer"`
	}{
		Index:      b.Index,
		HosID:      b.HosID,
		PrevHash:   b.PrevHash,
		Timestamp:  b.Timestamp,
		MerkleRoot: b.MerkleRoot,
		Proposer:   b.Proposer,
	}
	return sha256Hex(jsonCanonical(hdr))
}
