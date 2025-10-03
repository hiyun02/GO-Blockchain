package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
)

// 피어 리스트
var peers []string
var peerMu sync.Mutex

// broadcastBlock : 연결된 모든 피어에게 블록 브로드캐스트
// Geth의 peer broadcast 개념을 단순화한 구현
func broadcastBlock(block Block) {
	peerMu.Lock()
	defer peerMu.Unlock()

	data, _ := json.Marshal(block)
	for _, peer := range peers {
		url := "http://" + peer + "/receive"
		go func(peerURL string) {
			_, err := http.Post(peerURL, "application/json", strings.NewReader(string(data)))
			if err != nil {
				log.Printf("[P2P] Failed to send block to %s: %v\n", peerURL, err)
			} else {
				log.Printf("[P2P] Block broadcasted to %s\n", peerURL)
			}
		}(url)
	}
}

// receiveBlock : 다른 노드가 전송한 블록 수신
// Geth의 "Block Propagation → validate → add to chain" 개념 참고
func receiveBlock(w http.ResponseWriter, r *http.Request) {
	var newBlock Block
	body, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(body, &newBlock)

	mu.Lock()
	oldBlock := blockchain[len(blockchain)-1]
	mu.Unlock()

	if validateBlock(newBlock, oldBlock) && validatePoW(newBlock) {
		mu.Lock()
		blockchain = append(blockchain, newBlock)
		saveBlockToDB(newBlock)
		updateHashTable(newBlock)
		mu.Unlock()
		log.Printf("[P2P] Block received and added: #%d (Hash=%s)\n", newBlock.Header.Index, newBlock.Header.Hash)

		// 추가로, 새 블록을 다른 피어들에게도 전파 (gossip 방식)
		go broadcastBlock(newBlock)
	} else {
		log.Println("[P2P] Invalid block received, discarded")
	}
}

// syncChain : 새 노드가 부트노드 또는 다른 노드에게 전체 체인 요청
func syncChain(peer string) {
	url := "http://" + peer + "/chain"
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("[P2P] Failed to sync from %s: %v\n", peer, err)
		return
	}
	defer resp.Body.Close()

	var peerChain []Block
	json.NewDecoder(resp.Body).Decode(&peerChain)

	mu.Lock()
	if len(peerChain) > len(blockchain) && validateBlock(peerChain[0], blockchain[0]) {
		blockchain = peerChain
		log.Printf("[P2P] Chain synced from %s (length=%d)\n", peer, len(peerChain))
	}
	mu.Unlock()
}
