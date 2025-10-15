package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// 블록체인 전체 (메모리 상의 배열) + 동시성 제어용 뮤텍스
var blockchain []Block
var mu sync.Mutex

// 제네시스 블록(맨 처음 블록) 생성
func createGenesisBlock() Block {
	genesisInfo := map[string]string{
		"title":    "Genesis Block",
		"category": "system",
		"creator":  "network",
	}

	entry := ContentRecord{
		ContentID:   "GENESIS",
		Info:        genesisInfo,
		Fingerprint: Sha256Hex([]byte("Genesis Block")),
		StorageAddr: "local://genesis",
		Timestamp:   time.Now().Format(time.RFC3339),
	}
	genesis := Block{
		Header: BlockHeader{
			Index:      0,
			Timestamp:  time.Now().Format(time.RFC3339),
			PrevHash:   "",
			MerkleRoot: "",
			Nonce:      0,
		},
		Entries: []ContentRecord{entry},
	}
	leaf := HashContentRecord(entry)
	genesis.Header.MerkleRoot = MerkleRootHex([]string{leaf})
	// 제네시스 블록 해시
	genesis.Header.Hash = calculateHash(genesis)
	return genesis
}

// 신규 블록을 생성하고 체인에 추가
// • 각 콘텐츠 info를 기반으로 ContentRecord를 생성
// • Fingerprint는 시스템이 JSON 내용을 해싱하여 자동 생성
// • 모든 ContentRecord 해시를 머클 트리로 결합하여 MerkleRoot 계산
// • PoW(작업증명)를 수행해 블록 헤더의 Nonce와 Hash를 결정
func addBlock(contents []map[string]string) Block {
	mu.Lock()
	defer mu.Unlock()

	prevBlock := blockchain[len(blockchain)-1]

	// ContentRecord 생성하여 Header + Entries를 직접 구성
	var entries []ContentRecord
	for i, info := range contents {
		// 컨텐츠 내용 해시
		fingerprint := Sha256Hex(JsonCanonical(info))

		entries = append(entries, ContentRecord{
			ContentID:   generateContentID(prevBlock.Header.Index, i),
			Info:        info,
			Fingerprint: fingerprint,
			StorageAddr: info["storage_addr"],
			Timestamp:   time.Now().Format(time.RFC3339),
		})
	}

	// Merkle Root 계산
	var leafHashes []string
	for _, e := range entries {
		leafHashes = append(leafHashes, HashContentRecord(e))
	}
	merkleRoot := MerkleRootHex(leafHashes)

	// 신규 블록 구성
	newBlk := Block{
		Header: BlockHeader{
			Index:      prevBlock.Header.Index + 1,
			Timestamp:  time.Now().Format(time.RFC3339),
			PrevHash:   prevBlock.Header.Hash,
			MerkleRoot: merkleRoot,
			Nonce:      0,
			Hash:       "",
		},
		Entries: entries,
	}

	// PoW 실행
	hash, nonce := proofOfWork(newBlk)
	newBlk.Header.Hash = hash
	newBlk.Header.Nonce = nonce

	// 블록체인에 추가
	blockchain = append(blockchain, newBlk)

	// 블록 생성 로깅
	log.Printf("[BLOCKCHAIN] Block #%d created | Entries=%d | Hash=%s | MerkleRoot=%s\n",
		newBlk.Header.Index, len(entries), newBlk.Header.Hash, newBlk.Header.MerkleRoot)
	return newBlk
}

// 블록 인덱스와 콘텐츠 순번을 조합해 고유 ID 생성
// 예) Block #3의 첫 번째 콘텐츠 : "B3-E0"
func generateContentID(blockIndex int, entryIndex int) string {
	return fmt.Sprintf("B%d-E%d", blockIndex, entryIndex)
}

// 새 블록이 올바른지 검증
// • 인덱스 순서, 이전 해시 일치, 블록 헤더 해시(PoW) 검증
// • 추가로 MerkleRoot 재계산을 통해 Entries 변조 여부 검증
func validateBlock(newBlk, oldBlk Block) bool {
	// 순서 검증
	if oldBlk.Header.Index+1 != newBlk.Header.Index {
		return false
	}
	// 이전 해시 검증
	if oldBlk.Header.Hash != newBlk.Header.PrevHash {
		return false
	}
	// MerkleRoot 검증 (Entries 변조 방지)
	var leafHashes []string
	for _, e := range newBlk.Entries {
		leafHashes = append(leafHashes, HashContentRecord(e))
	}
	expectedMerkle := MerkleRootHex(leafHashes)
	if newBlk.Header.MerkleRoot != expectedMerkle {
		return false
	}
	// 블록 헤더 해시 검증
	if calculateHash(newBlk) != newBlk.Header.Hash {
		return false
	}
	return true
}
