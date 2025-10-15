package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
)

// 현재 블록체인 반환
// GET /chain
func getBlockchain(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blockchain)
}

// 새 블록 채굴
// POST /mine : 새 블록 채굴 (복수 콘텐츠 등록 가능)
// 요청 Body 예시:
// [
//
//	{"title":"AI Lecture","category":"Education","storage_addr":"ipfs://hash1"},
//	{"title":"Quantum Talk","category":"Science","storage_addr":"ipfs://hash2"}
//
// ]
func mineBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var contents []map[string]string
	if err := json.NewDecoder(r.Body).Decode(&contents); err != nil {
		http.Error(w, "invalid JSON format", http.StatusBadRequest)
		return
	}

	// 새 블록 생성
	newBlock := addBlock(contents)

	// DB 저장
	saveBlockToDB(newBlock)
	updateHashTable(newBlock)

	log.Printf("[API] ✅ New block mined: #%d | Entries=%d | Hash=%s\n",
		newBlock.Header.Index, len(newBlock.Entries), newBlock.Header.Hash)

	// 응답 반환
	json.NewEncoder(w).Encode(newBlock)

	// P2P 브로드캐스트 (다른 노드로 전파)
	go broadcastBlock(newBlock)
}

// 현재 노드가 알고 있는 피어 리스트 반환
// GET /peers
func getPeers(w http.ResponseWriter, r *http.Request) {
	peerMu.Lock()
	defer peerMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

// 새로운 피어 등록
// POST /addPeer (Body: "ip:port")
func addPeer(w http.ResponseWriter, r *http.Request) {
	var peer string
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, "invalid peer format", http.StatusBadRequest)
		return
	}

	peerMu.Lock()
	peers = append(peers, peer)
	peerMu.Unlock()

	log.Printf("[API] New peer added: %s\n", peer)
	w.Write([]byte("Peer added"))
}

// ------------------------------------------------------------
// 인덱스로 블록 조회
// GET /block/index?id=<int>
// ------------------------------------------------------------
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

// ------------------------------------------------------------
// 블록 해시로 조회
// GET /block/index?value=<hash>
// ------------------------------------------------------------
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

// ------------------------------------------------------------
// 콘텐츠 키워드 검색
// ------------------------------------------------------------
// GET /block/content?value=<keyword>
// - keyword가 ContentID, Fingerprint, Info(title 등) 중 하나와 일치 시 해당 블록 반환
// ------------------------------------------------------------
func getBlockByContentAPI(w http.ResponseWriter, r *http.Request) {
	keyword := r.URL.Query().Get("value")
	if keyword == "" {
		http.Error(w, "value parameter required", http.StatusBadRequest)
		return
	}

	block, err := getBlockByContent(keyword)
	if err != nil {
		http.Error(w, "block not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(block)
}
