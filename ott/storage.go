package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/syndtr/goleveldb/leveldb"
)

// 전역 DB 핸들
var db *leveldb.DB

// LevelDB 객체 초기화
func initDB(path string) {
	var err error
	db, err = leveldb.OpenFile(path, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[DB] LevelDB initialized at", path)
}

// LevelDB 객체 닫기
func closeDB() {
	db.Close()
	log.Println("[DB] Closed LevelDB")
}

// 블록을 LevelDB에 저장
// - Key1: "block_<Index>" => 블록 전체 JSON
// - Key2: "hash_<BlockHash>" => 블록 전체 JSON
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

// ------------------------------------------------------------
// 블록 내 각 컨텐츠(ContentRecord) 검색 HashTable 저장
// ------------------------------------------------------------
// Key-Value 예시:
//
//	"cid_<ContentID>"  => BlockHash (컨텐츠 ID 기반)
//	"fp_<Fingerprint>" => BlockHash	(Fingerprint 기반)
//	"info_<keyword>"   => BlockHash (제목, 카테고리 등 메타데이터 기반)
//
// ------------------------------------------------------------
func updateHashTable(block Block) {
	for _, entry := range block.Entries {
		// 컨텐츠 ID 기반 Hash 검색
		keyByCID := fmt.Sprintf("cid_%s", entry.ContentID)
		db.Put([]byte(keyByCID), []byte(block.Header.Hash), nil)

		// Fingerprint 기반 Hash 검색
		keyByFP := fmt.Sprintf("fp_%s", entry.Fingerprint)
		db.Put([]byte(keyByFP), []byte(block.Header.Hash), nil)

		// 메타데이터 Key-Value 기반 단순 텍스트
		for k, v := range entry.Info {
			if v == "" {
				continue
			}
			key := fmt.Sprintf("info_%s_%s", k, strings.ToLower(v))
			db.Put([]byte(key), []byte(block.Header.Hash), nil)
		}
	}
	log.Printf("[DB] Hash index updated for Block #%d (%d entries)\n",
		block.Header.Index, len(block.Entries))
}

// ------------------------------------------------------------
// 인덱스로 블록 조회
// ------------------------------------------------------------
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

// ------------------------------------------------------------
// 블록 해시로 조회
// ------------------------------------------------------------
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

// ------------------------------------------------------------
// 컨텐츠 키워드로 블록 검색
// ------------------------------------------------------------
// 검색 키워드가 Info의 일부거나 ContentID, Fingerprint에 일치하면 해당 블록 반환
// ------------------------------------------------------------
func getBlockByContent(keyword string) (Block, error) {
	// 컨텐츠 ID 색인 조회
	keyCID := fmt.Sprintf("cid_%s", keyword)
	if hash, err := db.Get([]byte(keyCID), nil); err == nil {
		return getBlockByHash(string(hash))
	}

	// Fingerprint 색인 조회
	keyFP := fmt.Sprintf("fp_%s", keyword)
	if hash, err := db.Get([]byte(keyFP), nil); err == nil {
		return getBlockByHash(string(hash))
	}

	// Info 필드 기반 색인 조회
	keyInfo := fmt.Sprintf("info_title_%s", strings.ToLower(keyword))
	if hash, err := db.Get([]byte(keyInfo), nil); err == nil {
		return getBlockByHash(string(hash))
	}

	return Block{}, fmt.Errorf("no block found for keyword: %s", keyword)
}
