package main

import (
	"log"
	"sync"
)

// 블록체인 전체 (메모리 상의 배열) + 동시성 제어용 뮤텍스
var blockchain []Block
var mu sync.Mutex

// createGenesisBlock : 제네시스 블록(맨 처음 블록) 생성
func createGenesisBlock() Block {
	genesis := Block{
		Header: BlockHeader{
			Index:     0,
			Timestamp: "2025-01-01 00:00:00", // 고정된 값
			PrevHash:  "",
			Nonce:     0,
		},
		Payload: BlockPayload{
			Data: "Genesis Block",
		},
	}
	// 제네시스 블록 해시
	genesis.Header.Hash = calculateHash(genesis)
	return genesis
}

// addBlock : 새로운 데이터를 받아서 블록을 생성하고 체인에 추가
// 여기서 PoW(proofOfWork) 실행해서 유효한 Nonce/Hash 찾음
func addBlock(data string) Block {
	mu.Lock()
	defer mu.Unlock()

	prevBlock := blockchain[len(blockchain)-1]
	var contentInfo map[string]string
	newBlk := newBlock(prevBlock.Header.Index+1, prevBlock.Header.Hash, contentInfo)

	// PoW 실행
	hash, nonce := proofOfWork(newBlk)
	newBlk.Header.Hash = hash
	newBlk.Header.Nonce = nonce

	// 블록체인에 추가
	blockchain = append(blockchain, newBlk)

	log.Printf("[BLOCKCHAIN] Block #%d created, Hash=%s\n", newBlk.Header.Index, newBlk.Header.Hash)
	return newBlk
}

// validateBlock : 새로운 블록이 올바른지 검증
func validateBlock(newBlk, oldBlk Block) bool {
	if oldBlk.Header.Index+1 != newBlk.Header.Index {
		return false
	}
	if oldBlk.Header.Hash != newBlk.Header.PrevHash {
		return false
	}
	if calculateHash(newBlk) != newBlk.Header.Hash {
		return false
	}
	return true
}
