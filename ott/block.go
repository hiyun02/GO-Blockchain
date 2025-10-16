package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
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

// B하나의 블록 = Header + Entries
// 기존 Payload 구조 대신 여러 컨텐츠를 담는 형태
type Block struct {
	Header  BlockHeader     `json:"header"`
	Entries []ContentRecord `json:"entries"`
}

// 블록의 해시값 계산
// Index, Timestamp, Data, PrevHash, Nonce, MerkleRoot 를 모두 이용하여 SHA-256 해시 생성
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

// 새 블록 생성 함수 (PoW 적용은 blockchain.go에서 처리)
func newBlock(index int, prevHash string, contentInfo map[string]string) Block {
	entry := ContentRecord{
		ContentID:   fmt.Sprintf("rec_%d", index),
		Info:        contentInfo,
		Fingerprint: Sha256Hex([]byte(contentInfo["title"])), // 예시
		StorageAddr: "local://dummy/path",
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	block := Block{
		Header: BlockHeader{
			Index:      index,
			Timestamp:  time.Now().Format(time.RFC3339),
			PrevHash:   prevHash,
			MerkleRoot: "", // Merkle 계산 후에 업데이트
			Nonce:      0,  // Nonce 계산 후에 업데이트
		},
		Entries: []ContentRecord{entry},
	}
	return block
}
