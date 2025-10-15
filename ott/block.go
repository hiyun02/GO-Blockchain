package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// 블록의 메타데이터
type BlockHeader struct {
	Index      int    `json:"index"`       // 블록 번호
	Timestamp  string `json:"timestamp"`   // 생성 시간
	PrevHash   string `json:"prev_hash"`   // 이전 블록의 해시
	MerkleRoot string `json:"merkle_root"` // 블록 내부 데이터의 요약 해시(머클루트)
	Hash       string `json:"hash"`        // 현재 블록의 해시
	Nonce      int    `json:"nonce"`       // 작업증명에 사용된 값
}

// 하나의 블록 = Header + Entries
// 기존 Payload 구조 대신 여러 컨텐츠를 담는 형태
type Block struct {
	Header  BlockHeader     `json:"header"`
	Entries []ContentRecord `json:"entries"`
}

// 블록의 해시값 계산
// Index, Timestamp, Data, PrevHash, Nonce, MerkleRoot 를 모두 이용하여 SHA-256 해시 생성
// Entries(콘텐츠 데이터)는 MerkleRoot로 간접적으로 반영됨
// 블록 해시는 블록 간 연결(체인 구조)과 PoW 검증에 사용되고,
// 개별 콘텐츠의 무결성은 Merkle 트리를 통해 검증됨
func calculateHash(block Block) string {
	record := strconv.Itoa(block.Header.Index) +
		block.Header.Timestamp +
		block.Header.PrevHash +
		block.Header.MerkleRoot +
		strconv.Itoa(block.Header.Nonce)

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}
