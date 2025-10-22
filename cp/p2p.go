package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

// -----------------------------------------------------------------------------
// Peer 관리
// -----------------------------------------------------------------------------
var peers []string
var peerMu sync.Mutex

// -----------------------------------------------------------------------------
// 내부 체인 상태 보호용 뮤텍스
//   - LevelDB는 동시 호출 가능하지만, "마지막 블록 로드 -> 새 블록 검증/저장" 시퀀스는
//     로컬 노드 내에서 직렬화하는 편이 안전함 (경쟁 수신/동기화 방지).
//
// -----------------------------------------------------------------------------
var chainMu sync.Mutex

// -----------------------------------------------------------------------------
// 블록 검증 (확정형)
// - 순서: index 증가, prevHash 일치
// - 머클루트/블록해시 재계산 일치
// - cp_id 일치(제네시스와 동일 체인인지 확인)
// -----------------------------------------------------------------------------
func validateLowerBlock(newBlk, prevBlk LowerBlock) error {
	// 1) 인덱스 연속성
	if prevBlk.Index+1 != newBlk.Index {
		return fmt.Errorf("index not consecutive: prev=%d new=%d", prevBlk.Index, newBlk.Index)
	}
	// 2) 이전 해시 연동
	if prevBlk.BlockHash != newBlk.PrevHash {
		return fmt.Errorf("prev_hash mismatch: want=%s got=%s", prevBlk.BlockHash, newBlk.PrevHash)
	}
	// 3) cp_id 일치
	if prevBlk.CpID != newBlk.CpID {
		return fmt.Errorf("cp_id mismatch: chain=%s new=%s", prevBlk.CpID, newBlk.CpID)
	}
	// 4) MerkleRoot 재계산
	leaf := make([]string, len(newBlk.Entries))
	for i, r := range newBlk.Entries {
		leaf[i] = hashContentRecord(r)
	}
	expectedRoot := merkleRootHex(leaf)
	if expectedRoot != newBlk.MerkleRoot {
		return fmt.Errorf("merkle_root mismatch")
	}
	// 5) BlockHash 재계산
	if newBlk.computeHash() != newBlk.BlockHash {
		return fmt.Errorf("block_hash mismatch")
	}
	return nil
}

// -----------------------------------------------------------------------------
// 브로드캐스트: 연결된 모든 피어에 LowerBlock POST /receive
// -----------------------------------------------------------------------------
func broadcastBlock(block LowerBlock) {
	peerMu.Lock()
	targets := append([]string(nil), peers...)
	peerMu.Unlock()

	data, _ := json.Marshal(block)

	for _, peer := range targets {
		url := "http://" + peer + "/receive"
		go func(peerURL string, body []byte) {
			resp, err := http.Post(peerURL, "application/json", strings.NewReader(string(body)))
			if err != nil {
				log.Printf("[P2P] Failed to send block to %s: %v\n", peerURL, err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			log.Printf("[P2P] Block broadcasted to %s (status=%d)\n", peerURL, resp.StatusCode)
		}(url, data)
	}
}

// -----------------------------------------------------------------------------
// 수신 핸들러: POST /receive
// - 새 블록 수신 → 로컬 최신 블록과 검증 → 저장/색인/메타 업데이트
// - 중복/역행/불일치 시 거절
// -----------------------------------------------------------------------------
func receiveBlock(w http.ResponseWriter, r *http.Request) {
	var newBlock LowerBlock
	if err := json.NewDecoder(r.Body).Decode(&newBlock); err != nil {
		http.Error(w, "invalid block data", http.StatusBadRequest)
		return
	}

	chainMu.Lock()
	defer chainMu.Unlock()

	// 제네시스는 로컬 부팅(NewLowerChain)에서 이미 생성되어 있다고 가정.
	// 최신 높이 로드
	lastH, ok := getLatestHeight()
	if !ok {
		http.Error(w, "local chain not initialized (height meta missing)", http.StatusServiceUnavailable)
		return
	}
	prevBlk, err := getBlockByIndex(lastH)
	if err != nil {
		http.Error(w, "failed to load last block", http.StatusInternalServerError)
		return
	}

	// 역행/중복 방지
	if newBlock.Index <= prevBlk.Index {
		http.Error(w, "stale or duplicate block", http.StatusConflict)
		return
	}

	// 검증
	if err := validateLowerBlock(newBlock, prevBlk); err != nil {
		log.Printf("[P2P] Invalid block received: %v\n", err)
		http.Error(w, "invalid block: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 저장/색인/메타 (원자성 향상 필요 시 leveldb.Batch 사용 고려)
	if err := saveBlockToDB(newBlock); err != nil {
		http.Error(w, "save block error", http.StatusInternalServerError)
		return
	}
	if err := updateIndicesForBlock(newBlock); err != nil {
		http.Error(w, "update indices error", http.StatusInternalServerError)
		return
	}
	if err := setLatestHeight(newBlock.Index); err != nil {
		http.Error(w, "set height error", http.StatusInternalServerError)
		return
	}

	log.Printf("[P2P] Block accepted: #%d | Hash=%s | Entries=%d\n",
		newBlock.Index, newBlock.BlockHash, len(newBlock.Entries))

	// gossip 재전파 (선택)
	go broadcastBlock(newBlock)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("block accepted"))
}

// -----------------------------------------------------------------------------
// 체인 동기화: 원격 노드 /blocks (페이지네이션) 기반으로 로컬의 뒤쪽만 채움
// - 원격 total <= 로컬 total : up-to-date
// - 원격 total > 로컬 total : 로컬 height+1 부터 순서대로 검증/append
// -----------------------------------------------------------------------------
type blocksPage struct {
	Total  int          `json:"total"`
	Offset int          `json:"offset"`
	Limit  int          `json:"limit"`
	Items  []LowerBlock `json:"items"`
}

func syncChain(peer string) {
	// 로컬 상태
	chainMu.Lock()
	localH, ok := getLatestHeight()
	if !ok {
		chainMu.Unlock()
		log.Printf("[P2P] Local chain not initialized (height meta missing)\n")
		return
	}
	chainMu.Unlock()

	baseURL := "http://" + peer + "/blocks"
	offset := 0
	limit := 256 // 페이지 크기 (조정 가능)
	var remoteTotal int
	appended := 0

	for {
		// 원격 페이지 요청
		url := fmt.Sprintf("%s?offset=%d&limit=%d", baseURL, offset, limit)
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("[P2P] Failed to sync from %s: %v\n", peer, err)
			return
		}
		var page blocksPage
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			_ = resp.Body.Close()
			log.Printf("[P2P] Invalid /blocks page from %s: %v\n", peer, err)
			return
		}
		_ = resp.Body.Close()

		if offset == 0 {
			remoteTotal = page.Total
			// 원격이 더 길지 않으면 종료
			if remoteTotal <= localH+1 {
				log.Printf("[P2P] Up-to-date (local=%d, remote=%d)\n", localH+1, remoteTotal)
				return
			}
		}

		// 페이지 내 블록들 처리 (로컬 height+1 이후만)
		for _, nb := range page.Items {
			// 이미 가진 블록은 건너뜀
			if nb.Index <= localH {
				continue
			}
			chainMu.Lock()
			prev, err := getBlockByIndex(localH)
			if err != nil {
				chainMu.Unlock()
				log.Printf("[P2P] Load local prev error at %d: %v\n", localH, err)
				return
			}
			if err := validateLowerBlock(nb, prev); err != nil {
				chainMu.Unlock()
				log.Printf("[P2P] Remote block invalid at #%d: %v\n", nb.Index, err)
				return
			}
			// append
			if err := saveBlockToDB(nb); err != nil {
				chainMu.Unlock()
				log.Printf("[P2P] saveBlockToDB error: %v\n", err)
				return
			}
			if err := updateIndicesForBlock(nb); err != nil {
				chainMu.Unlock()
				log.Printf("[P2P] updateIndicesForBlock error: %v\n", err)
				return
			}
			if err := setLatestHeight(nb.Index); err != nil {
				chainMu.Unlock()
				log.Printf("[P2P] setLatestHeight error: %v\n", err)
				return
			}
			localH = nb.Index
			appended++
			chainMu.Unlock()
		}

		offset += limit
		if offset >= remoteTotal {
			break
		}
	}

	log.Printf("[P2P] Chain synced from %s (+%d blocks, new height=%d)\n", peer, appended, localH)
}

// p2p.go
// 신규 노드가 부트노드에 자기 주소를 등록하고,
// 현재 피어 목록을 받아가도록 하는 엔드포인트.
type registerReq struct {
	Addr string `json:"addr"` // "host:port" 또는 "컨테이너명:포트"
	CpID string `json:"cp_id"`
}
type registerResp struct {
	Peers []string `json:"peers"`
}

// 신규노드가 네트워크 진입 시 부트노드에게 다른 노드들의 주소를 제공받기 위한 함수
func registerPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Addr == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	// 체인 정체성 확인: 제네시스 cp_id와 일치해야 가입 허용
	blk0, err := getBlockByIndex(0)
	if err != nil || blk0.CpID != req.CpID {
		http.Error(w, "cp_id mismatch", http.StatusForbidden)
		return
	}

	// 부트노드 로컬 peers에 추가
	peerMu.Lock() // 동시 접근 막음
	already := false
	// 이미 등록된 주소인지 검증
	for _, p := range peers {
		if p == req.Addr {
			already = true
			break
		}
	}
	// 등록된 주소가 아니라면 추가
	if !already {
		peers = append(peers, req.Addr)
		log.Printf("[P2P][REGISTER] new peer joined: %s (cp_id=%s) | total=%d", req.Addr, req.CpID, len(peers))
	} else {
		log.Printf("[P2P][REGISTER] peer already exists: %s", req.Addr)
	}
	// 응답으로 넘겨줄 피어목록을 만듦 (자기 자신은 제외)
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		if p != req.Addr {
			out = append(out, p)
		}
	}
	peerMu.Unlock()

	// 기존 피어들에게도 새 피어 알려주기(비동기)
	go func(newPeer string, others []string) {
		log.Printf("[P2P][REGISTER] notifying %d existing peers about %s", len(others), newPeer)
		b, _ := json.Marshal(newPeer)
		for _, op := range others {
			_, _ = http.Post("http://"+op+"/addPeer", "application/json", strings.NewReader(string(b)))
			if err != nil {
				log.Printf("[P2P][REGISTER] notify failed to %s: %v", op, err)
			}
		}
	}(req.Addr, out)

	// 신규 노드에게 현재 피어 목록을 응답
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(registerResp{Peers: out})
}
