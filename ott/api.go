package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
)

// getBlockchain : 현재 블록체인 반환
// GET /chain
func getBlockchain(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blockchain)
}

// mineBlock : 새 블록 채굴
// POST /mine (Body: 데이터 문자열)
func mineBlock(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	data := string(body)

	// 새 블록 추가
	newBlock := addBlock(data)

	// DB 저장
	saveBlockToDB(newBlock)
	updateHashTable(newBlock)

	log.Printf("[API] New block mined: #%d (Hash=%s)\n", newBlock.Header.Index, newBlock.Header.Hash)

	// 응답 반환
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newBlock)

	// P2P 브로드캐스트
	broadcastBlock(newBlock)
}

// getPeers : 현재 노드가 알고 있는 피어 리스트 반환
// GET /peers
func getPeers(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

// addPeer : 새로운 피어 등록
// POST /addPeer (Body: "ip:port")
func addPeer(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	peer := string(body)

	mu.Lock()
	peers = append(peers, peer)
	mu.Unlock()

	log.Printf("[API] New peer added: %s\n", peer)
	w.Write([]byte("Peer added"))
}

// getBlockByIndexAPI : 블록 인덱스로 장부 조회
// GET /block/index?id=0
func getBlockByIndexAPI(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("id")
	if query == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	index, err := strconv.Atoi(query)
	if err != nil {
		http.Error(w, "id must be integer", http.StatusBadRequest)
		return
	}

	block, err := getBlockByIndex(index)
	if err != nil {
		http.Error(w, "block not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(block)
}

// getBlockByHashAPI : 블록 해시로 장부 조회
// GET /block/hash?value=<hash>
func getBlockByHashAPI(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("value")
	if hash == "" {
		http.Error(w, "value parameter required", http.StatusBadRequest)
		return
	}

	block, err := getBlockByHash(hash)
	if err != nil {
		http.Error(w, "block not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(block)
}

// getBlockByPayloadAPI : Payload 값으로 해시테이블 검색
// GET /block/payload?value=MyData
func getBlockByPayloadAPI(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("value")
	if data == "" {
		http.Error(w, "value parameter required", http.StatusBadRequest)
		return
	}

	block, err := getBlockByPayload(data)
	if err != nil {
		http.Error(w, "block not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(block)
}
