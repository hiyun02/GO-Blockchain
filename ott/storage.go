package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/syndtr/goleveldb/leveldb"
)

// 전역 DB 핸들
var db *leveldb.DB

// initDB : LevelDB 초기화
func initDB(path string) {
	var err error
	db, err = leveldb.OpenFile(path, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[DB] LevelDB initialized at", path)
}

// closeDB : LevelDB 닫기
func closeDB() {
	db.Close()
	log.Println("[DB] Closed LevelDB")
}

// saveBlockToDB : 블록을 LevelDB에 저장
// - Key1: "block_<Index>" → 블록 전체 JSON
// - Key2: "hash_<BlockHash>" → 블록 전체 JSON
func saveBlockToDB(block Block) {
	data, _ := json.Marshal(block)

	// 블록 번호 기반 저장
	keyByIndex := fmt.Sprintf("block_%d", block.Header.Index)
	db.Put([]byte(keyByIndex), data, nil)

	// 블록 해시 기반 저장
	keyByHash := fmt.Sprintf("hash_%s", block.Header.Hash)
	db.Put([]byte(keyByHash), data, nil)

	log.Printf("[DB] Block #%d saved (Hash=%s)\n", block.Header.Index, block.Header.Hash)
}

// updateHashTable : 해시테이블(검색 인덱스) 저장
// 예: "payload_<Data>" → BlockHash
func updateHashTable(block Block) {
	key := fmt.Sprintf("payload_%s", block.Payload.Data)
	value := block.Header.Hash
	db.Put([]byte(key), []byte(value), nil)

	log.Printf("[DB] HashTable updated: %s → %s\n", key, value)
}

// getBlockByIndex : 인덱스로 블록 조회
func getBlockByIndex(index int) (Block, error) {
	key := fmt.Sprintf("block_%d", index)
	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return Block{}, err
	}
	var block Block
	json.Unmarshal(data, &block)
	return block, nil
}

// getBlockByHash : 해시로 블록 조회
func getBlockByHash(hash string) (Block, error) {
	key := fmt.Sprintf("hash_%s", hash)
	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return Block{}, err
	}
	var block Block
	json.Unmarshal(data, &block)
	return block, nil
}

// getBlockByPayload : 데이터(payload) 키워드로 블록 찾기
func getBlockByPayload(data string) (Block, error) {
	key := fmt.Sprintf("payload_%s", data)
	hash, err := db.Get([]byte(key), nil)
	if err != nil {
		return Block{}, err
	}
	return getBlockByHash(string(hash))
}
