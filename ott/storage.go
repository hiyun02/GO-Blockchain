package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

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

// ---- 키스페이스 (Upper/OTT 전용) --------------------------------------------
// 블록     : u_block_<idx>       => UpperBlock JSON
//           u_uhash_<hash>       => UpperBlock JSON
// 메타     : u_height_latest      => int (마지막 인덱스)
//           u_root_latest         => string (옵션: 마지막 UpperBlock root/hash 등)
// 계약     : u_contract_<cp_id>   => ContractData JSON
// 앵커     : u_anchor_<cp_id>     => AnchorState JSON {cp_id, lower_root, ts, sig}
// HMAC 키  : u_key_<cp_id>        => string(secret)

type AnchorState struct {
	CPID      string `json:"cp_id"`
	LowerRoot string `json:"lower_root"`
	Timestamp string `json:"ts"`
	Signature string `json:"sig"`
}

// ---- 메타 --------------------------------------------------------------------
func setHeightLatest(h int) error {
	return db.Put([]byte("u_height_latest"), []byte(strconv.Itoa(h)), nil)
}
func getHeightLatest() (int, bool) {
	b, err := db.Get([]byte("u_height_latest"), nil)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(string(b))
	if err != nil {
		return 0, false
	}
	return v, true
}

// ---- 블록 저장/조회 ----------------------------------------------------------
func saveBlock(blk UpperBlock) error {
	j, err := json.Marshal(blk)
	if err != nil {
		return err
	}
	if err := db.Put([]byte(fmt.Sprintf("u_block_%d", blk.Index)), j, nil); err != nil {
		return err
	}
	if err := db.Put([]byte("u_uhash_"+blk.BlockHash), j, nil); err != nil {
		return err
	}
	// 선택: 마지막 루트 캐시
	_ = db.Put([]byte("u_root_latest"), []byte(blk.BlockHash), nil)
	return nil
}
func getBlockByIndex(idx int) (UpperBlock, error) {
	b, err := db.Get([]byte(fmt.Sprintf("u_block_%d", idx)), nil)
	if err != nil {
		return UpperBlock{}, err
	}
	var blk UpperBlock
	if err := json.Unmarshal(b, &blk); err != nil {
		return UpperBlock{}, err
	}
	return blk, nil
}
func getBlockByHash(hash string) (UpperBlock, error) {
	b, err := db.Get([]byte("u_uhash_"+hash), nil)
	if err != nil {
		return UpperBlock{}, err
	}
	var blk UpperBlock
	if err := json.Unmarshal(b, &blk); err != nil {
		return UpperBlock{}, err
	}
	return blk, nil
}

// ---- 계약/앵커/키 ------------------------------------------------------------
func setContract(cpID string, c ContractData) error {
	j, _ := json.Marshal(c)
	return db.Put([]byte("u_contract_"+cpID), j, nil)
}
func getContract(cpID string) (ContractData, bool) {
	b, err := db.Get([]byte("u_contract_"+cpID), nil)
	if err != nil {
		return ContractData{}, false
	}
	var c ContractData
	if json.Unmarshal(b, &c) != nil {
		return ContractData{}, false
	}
	return c, true
}

func setAnchor(a AnchorState) error {
	j, _ := json.Marshal(a)
	return db.Put([]byte("u_anchor_"+a.CPID), j, nil)
}
func getAnchor(cpID string) (AnchorState, bool) {
	b, err := db.Get([]byte("u_anchor_"+cpID), nil)
	if err != nil {
		return AnchorState{}, false
	}
	var a AnchorState
	if json.Unmarshal(b, &a) != nil {
		return AnchorState{}, false
	}
	return a, true
}

func setHMACKey(cpID, secret string) error {
	return db.Put([]byte("u_key_"+cpID), []byte(secret), nil)
}
func getHMACKey(cpID string) (string, bool) {
	b, err := db.Get([]byte("u_key_"+cpID), nil)
	if err != nil {
		return "", false
	}
	return string(b), true
}
