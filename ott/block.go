package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// BlockHeader : 블록의 메타데이터
type BlockHeader struct {
	Index     int    `json:"index"`     // 블록 번호
	Timestamp string `json:"timestamp"` // 생성 시간
	PrevHash  string `json:"prev_hash"` // 이전 블록의 해시
	Hash      string `json:"hash"`      // 현재 블록의 해시
	Nonce     int    `json:"nonce"`     // 작업증명에 사용된 값
}

// BlockPayload : 블록에 들어가는 실제 데이터
// OTT/CP 데이터는 나중에 여기에 확장해서 넣으면 됨
type BlockPayload struct {
	Data string `json:"data"`
}

// Block : 하나의 블록 = Header + Payload
type Block struct {
	Header  BlockHeader  `json:"header"`
	Payload BlockPayload `json:"payload"`
}

// calculateHash : 블록의 해시값 계산
// Index, Timestamp, Data, PrevHash, Nonce 를 모두 연결해서 SHA-256 해시 생성
func calculateHash(block Block) string {
	record := strconv.Itoa(block.Header.Index) +
		block.Header.Timestamp +
		block.Payload.Data +
		block.Header.PrevHash +
		strconv.Itoa(block.Header.Nonce)

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// newBlock : 새 블록을 만드는 기본 함수 (PoW 적용은 blockchain.go에서 처리)
func newBlock(index int, prevHash string, data string) Block {
	block := Block{
		Header: BlockHeader{
			Index:     index,
			Timestamp: time.Now().String(),
			PrevHash:  prevHash,
			Nonce:     0,
		},
		Payload: BlockPayload{
			Data: data,
		},
	}
	return block
}
