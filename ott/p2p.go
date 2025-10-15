package main

import (
	"encoding/json"
	"io"
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
			resp, err := http.Post(peerURL, "application/json", strings.NewReader(string(data)))
			if err != nil {
				log.Printf("[P2P] Failed to send block to %s: %v\n", peerURL, err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			log.Printf("[P2P] Block broadcasted to %s\n", peerURL)

		}(url)
	}
}

// 다른 노드가 채굴한 신규 블록 수신
// - 외부 노드가 새 블록을 POST하면 실행됨
// - 새 블록이 유효한지 검증 (Index, PrevHash, MerkleRoot, PoW)
// - 검증 통과 시 blockchain에 append
func receiveBlock(w http.ResponseWriter, r *http.Request) {
	var newBlock Block
	if err := json.NewDecoder(r.Body).Decode(&newBlock); err != nil {
		http.Error(w, "invalid block data", http.StatusBadRequest)
		return
	}

	mu.Lock()
	lastBlock := blockchain[len(blockchain)-1]
	mu.Unlock()

	// 블록 유효성 검증 (순서 + PoW + MerkleRoot)
	if validateBlock(newBlock, lastBlock) && validatePoW(newBlock) {
		mu.Lock()
		blockchain = append(blockchain, newBlock)
		saveBlockToDB(newBlock)
		updateHashTable(newBlock)
		mu.Unlock()

		log.Printf("[P2P] Block received and added: #%d | Hash=%s | Entries=%d\n",
			newBlock.Header.Index, newBlock.Header.Hash, len(newBlock.Entries))

		// gossip 방식으로 다른 피어에게도 재전파
		go broadcastBlock(newBlock)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("block accepted"))
	} else {
		log.Println("[P2P] Invalid block received, discarded")
		http.Error(w, "invalid block", http.StatusBadRequest)
	}
}

// ------------------------------------------------------------
// 새 노드가 기존 네트워크 노드로부터 전체 체인 동기화
// ------------------------------------------------------------
// - 연결된 피어 중 하나에게 GET /chain 요청
// - 내 체인보다 길고 유효하면 교체
// - validateBlock()을 순차적으로 호출하여 체인 무결성 검증
// ------------------------------------------------------------
func syncChain(peer string) {
	url := "http://" + peer + "/chain"
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("[P2P] Failed to sync from %s: %v\n", peer, err)
		return
	}
	defer resp.Body.Close()

	var peerChain []Block
	if err := json.NewDecoder(resp.Body).Decode(&peerChain); err != nil {
		log.Printf("[P2P] Invalid chain data from %s: %v\n", peer, err)
		return
	}

	// 유효성 검증 및 길이 비교
	mu.Lock()
	defer mu.Unlock()

	if len(peerChain) <= len(blockchain) {
		log.Printf("[P2P] Local chain already up-to-date (local=%d, peer=%d)\n",
			len(blockchain), len(peerChain))
		return
	}

	for i := 1; i < len(peerChain); i++ {
		if !validateBlock(peerChain[i], peerChain[i-1]) {
			log.Printf("[P2P] Invalid block at index %d from %s, aborting sync\n", i, peer)
			return
		}
	}

	blockchain = peerChain
	log.Printf("[P2P] Chain synced from %s (length=%d)\n", peer, len(peerChain))
}
