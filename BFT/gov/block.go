package main

import (
	"log"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////
// UpperBlock (Gov 체인 블록 구조)
// ------------------------------------------------------------
// Hos 체인으로부터 전달받은 서명된 MerkleRoot를 수집하여 하나의 상위 블록으로 요약함
// 각 UpperBlock은 Hos 루트들의 루트(MerkleRoot of roots)를 포함
////////////////////////////////////////////////////////////////////////////////

// Gov 체인의 블록 구조체
// --------------------------------------------------
// - 하나의 UpperBlock은 여러 Hos 체인들의 루트(anchor)를 포함
type UpperBlock struct {
	Index      int            `json:"index"`       // 블록 번호
	GovID      string         `json:"gov_id"`      // Gov 체인 식별자
	PrevHash   string         `json:"prev_hash"`   // 이전 블록의 해시
	Timestamp  string         `json:"timestamp"`   // 생성 시간 (RFC3339 형식)
	Records    []AnchorRecord `json:"records"`     // Hos 체인에서 제출한 AnchorRecord 목록
	MerkleRoot string         `json:"merkle_root"` // AnchorRecords 속 MerkleRoot들을 병합하여 계산한 상위 MerkleRoot
	Proposer   string         `json:"proposer"`    // 해당 블록의 합의 집행자
	Signatures []string       `json:"signatures"`  // 2f+1개 이상의 노드 서명 목록 (합의 증거)
	BlockHash  string         `json:"block_hash"`  // 블록 전체 해시
	Elapsed    float32        `json:"elapsed"`     // 채굴 소요 시간
}

// 제네시스 블록 생성
func createGenesisBlock(govID string) UpperBlock {
	log.Printf("[Blk] Start genesis block...") //

	genesis := UpperBlock{
		Index:      0,                       //
		GovID:      govID,                   //
		PrevHash:   strings.Repeat("0", 64), //
		Timestamp:  "2026-01-24T01:07:18Z",  // 실험 데이터 일관성 유지
		Records:    []AnchorRecord{},        //
		MerkleRoot: "",                      //
		Proposer:   "SYSTEM",                //
		Signatures: []string{},              //
		Elapsed:    0,                       //
	}

	genesis.BlockHash = genesis.computeHash()  //
	log.Printf("[Blk] Start genesis block...") //

	return genesis
}

// 블록의 식별자인 Hash 값 계산 (Hos의 computeHash와 완벽 호환)
func (b UpperBlock) computeHash() string {
	// 해시에 포함할 헤더 필드 정의 (Hos 구조와 동일)
	hdr := struct {
		Index      int    `json:"index"`
		GovID      string `json:"gov_id"`
		PrevHash   string `json:"prev_hash"`
		Timestamp  string `json:"timestamp"`
		MerkleRoot string `json:"merkle_root"`
		Proposer   string `json:"proposer"`
	}{
		Index:      b.Index,      //
		GovID:      b.GovID,      //
		PrevHash:   b.PrevHash,   //
		Timestamp:  b.Timestamp,  //
		MerkleRoot: b.MerkleRoot, //
		Proposer:   b.Proposer,   //
	}

	// Hos 체인과 동일한 sha256Hex 및 jsonCanonical 메커니즘 사용
	return sha256Hex(jsonCanonical(hdr)) //
}
