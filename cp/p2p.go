package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// Peer 관리
// -----------------------------------------------------------------------------
var peers []string
var peerMu sync.Mutex
var peerAliveMap = make(map[string]bool) // 노드 상태를 주소:생존여부 형태로 관리하는 맵
var aliveMu sync.RWMutex

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
	Total      int          `json:"total"`
	Offset     int          `json:"offset"`
	Limit      int          `json:"limit"`
	Items      []LowerBlock `json:"items"`
	Difficulty int          `json:"difficulty"`
}

// 입력받은 주소의 노드에게 장부 정보를 제공받는 함수
func syncChain(peer string) {
	baseURL := "http://" + peer + "/blocks"
	offset := 0
	limit := 256 // 페이지 크기 (조정 가능)
	var remoteTotal int
	appended := 0

	// 로컬 상태
	chainMu.Lock()
	localH, ok := getLatestHeight()
	chainMu.Unlock()

	// 제네시스가 없는 경우, localH를 -1로 설정하여
	// 아무 블록도 없음을 명확히 표현
	if !ok {
		localH = -1
		log.Printf("[P2P] No local blocks. Will fetch full chain from %s\n", peer)
	}

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
			if page.Difficulty > 0 && page.Difficulty != GlobalDifficulty {
				log.Printf("[P2P] Difficulty update from peer=%s -> %d", peer, page.Difficulty)
				GlobalDifficulty = page.Difficulty
			}

			// 로컬이 아무 블록도 없으면 전체 sync
			// 로컬이 있고 원격이 더 길지 않으면 종료
			if localH >= 0 && remoteTotal <= localH+1 {
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

			// 제네시스(블록0) 처리: prev가 없음 -> validate 불필요
			if nb.Index == 0 {
				log.Printf("[P2P] Fetching genesis from %s", peer)
			} else {
				// prev 블록 가져오기
				prev, err := getBlockByIndex(nb.Index - 1)
				if err != nil {
					chainMu.Unlock()
					log.Printf("[P2P] Missing prev block #%d while syncing\n", nb.Index-1)
					return
				}

				// 검증
				if err := validateLowerBlock(nb, prev); err != nil {
					chainMu.Unlock()
					log.Printf("[P2P] Remote block invalid at #%d: %v\n", nb.Index, err)
					return
				}
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

	// 생존 상태 초기화
	aliveMu.Lock()
	peerAliveMap[addr] = true
	aliveMu.Unlock()

	return true
}

// 자신을 제외한 나머지 노드들의 주소 반환
func peersSnapshot() []string {
	peerMu.Lock()
	defer peerMu.Unlock()
	out := make([]string, len(peers)) // nil 방지 (비어있으면 [])
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

// 노드를 주소 목록에서 삭제하는 함수
func removePeer(addr string) {
	peerMu.Lock()
	defer peerMu.Unlock()

	newList := peers[:0] // 재사용 슬라이스 (GC 최소화)
	for _, p := range peers {
		if p != addr {
			newList = append(newList, p)
		}
	}
	peers = newList

	// 상태맵에서도 제거
	aliveMu.Lock()
	delete(peerAliveMap, addr)
	aliveMu.Unlock()

	log.Printf("[WATCHER] Dead Pear removed: %s", addr)
}

// 특정 노드 주소와 상태를 입력받아 기록
func markAlive(addr string, status bool) {
	aliveMu.Lock()
	defer aliveMu.Unlock()
	peerAliveMap[addr] = status
}

// 네트워크 감시 루틴(전체 노드 생존 여부 확인)
func startNetworkWatcher() {
	log.Printf("[WATCHER] starting network watcher")
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for range t.C {
		log.Printf("[WATCHER] Conduct the Watcher's inspection")
		currentBoot := getBootAddr()
		if currentBoot == "" {
			continue
		}

		for _, addr := range peersSnapshot() {
			if addr == self {
				continue
			}

			_, ok := probeStatus(addr)
			if ok {
				markAlive(addr, true)
				continue
			}

			// 응답 없음 -> 제거 및 aliveMap 갱신
			markAlive(addr, false)
			log.Printf("[WATCHER] Trying to remove dead node: %s", addr)
			removePeer(addr)

			// 만약 죽은 노드가 부트노드였다면
			if addr == currentBoot {
				log.Printf("[WATCHER] bootnode %s is dead -> starting re-election", addr)
				electAndSwitch()
			}
		}
	}
}

// 모든 노드에 전파된 컨텐츠 엔트리를 수신하여 메모리풀에 추가
// POST : /receivePending 요청을 통해 트리거
func receivePending(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		Entries []ContentRecord `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer r.Body.Close()
	appendPending(msg.Entries)
	log.Printf("[P2P] Content Entries saved to Pending : %d", len(msg.Entries))
}
