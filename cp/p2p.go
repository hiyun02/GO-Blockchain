package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

// 입력받은 주소의 노드에게 장부 정보를 제공받는 함수
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

// 새로운 피어 등록
func addPeer(w http.ResponseWriter, r *http.Request) {
	var addr string
	if err := json.NewDecoder(r.Body).Decode(&addr); err != nil {
		http.Error(w, "invalid peer format", http.StatusBadRequest)
		return
	}
	if addPeerInternal(addr) {
		w.Write([]byte("Peer added"))
	} else {
		w.Write([]byte("Peer exists"))
	}
}

func addPeerInternal(addr string) bool {
	if addr == "" {
		return false
	}
	peerMu.Lock()
	defer peerMu.Unlock()
	// 중복 방지
	already := checkAddress(addr)
	if !already {
		peers = append(peers, addr)
	} else {
		return false
	}
	log.Printf("[P2P][ADD] peer added: %s | total=%d", addr, len(peers))
	return true
}

func peersSnapshot() []string {
	peerMu.Lock()
	defer peerMu.Unlock()
	out := make([]string, len(peers)) // nil 방지 (빈이면 [])
	copy(out, peers)
	return out
}

func checkAddress(address string) bool {
	answer := false
	// 이미 등록된 주소인지 검증
	for _, p := range peers {
		if p == address {
			answer = true
			break
		}
	}
	return answer
}
