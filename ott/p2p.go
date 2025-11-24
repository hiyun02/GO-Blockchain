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
// 블록 검증
// - 순서: index 증가, prevHash 일치
// - 머클루트/블록해시 재계산 일치
// - ott_id 일치(제네시스와 동일 체인인지 확인)
// -----------------------------------------------------------------------------
func validateUpperBlock(newBlk, prevBlk UpperBlock) error {
	// 1) 인덱스 연속성
	if prevBlk.Index+1 != newBlk.Index {
		return fmt.Errorf("index not consecutive: prev=%d new=%d", prevBlk.Index, newBlk.Index)
	}
	// 2) 이전 해시 연동
	if prevBlk.BlockHash != newBlk.PrevHash {
		return fmt.Errorf("prev_hash mismatch: want=%s got=%s", prevBlk.BlockHash, newBlk.PrevHash)
	}
	// 3) ott_id 일치
	if prevBlk.OttID != newBlk.OttID {
		return fmt.Errorf("ott_id mismatch: chain=%s new=%s", prevBlk.OttID, newBlk.OttID)
	}
	// 4) MerkleRoot 재계산
	expectedRoot := computeUpperMerkleRoot(newBlk.Records)
	if expectedRoot != newBlk.MerkleRoot {
		return fmt.Errorf("merkle_root mismatch: want=%s got=%s", expectedRoot, newBlk.MerkleRoot)
	}
	// 5) BlockHash 재계산
	blockHash := newBlk.BlockHash
	if blockHash != newBlk.BlockHash {
		return fmt.Errorf("block_hash mismatch")
	}

	// 6) PoW 난이도 검증
	if !validHash(blockHash, newBlk.Difficulty) {
		return fmt.Errorf("pow difficulty not satisfied (hash=%s diff=%d)",
			blockHash, newBlk.Difficulty)
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
	Items      []UpperBlock `json:"items"`
	Difficulty int          `json:"difficulty"`
}

// 입력받은 주소의 노드에게 장부 정보를 제공받는 함수
func syncChain(peer string) {
	url := "http://" + peer + "/blocks"

	// 원격에서 전체 블록 수신
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("[P2P] Failed to sync from %s: %v\n", peer, err)
		return
	}
	var page blocksPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		_ = resp.Body.Close()
		log.Printf("[P2P] Invalid /blocks from %s: %v\n", peer, err)
		return
	}
	resp.Body.Close()

	remoteTotal := page.Total
	appended := 0

	// 로컬 상태
	chainMu.Lock()
	localH, ok := getLatestHeight()
	chainMu.Unlock()

	if !ok {
		localH = -1
		log.Printf("[P2P] No local blocks. Full sync from %s\n", peer)
	}

	// 난이도 변화 감지
	if page.Difficulty > 0 && page.Difficulty != GlobalDifficulty {
		log.Printf("[P2P] Difficulty update from peer=%s -> %d", peer, page.Difficulty)
		GlobalDifficulty = page.Difficulty
	}

	// 원격이 최신보다 같거나 더 짧으면 필요 없음
	if localH >= 0 && remoteTotal <= localH+1 {
		log.Printf("[P2P] Up-to-date (local=%d, remote=%d)\n", localH+1, remoteTotal)
		return
	}

	// 전체 블록을 순서대로 처리
	for _, nb := range page.Items {
		chainMu.Lock()

		if nb.Index != 0 {
			prev, err := getBlockByIndex(nb.Index - 1)
			if err != nil {
				chainMu.Unlock()
				log.Printf("[P2P] Missing prev block #%d\n", nb.Index-1)
				return
			}

			// 블록 검증
			if err := validateUpperBlock(nb, prev); err != nil {
				chainMu.Unlock()
				log.Printf("[P2P] Remote block invalid at #%d: %v\n", nb.Index, err)
				return
			}
		} else {
			log.Printf("[P2P] Fetching genesis from %s", peer)
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

	log.Printf("[P2P] Chain synced from %s (+%d blocks, new height=%d)\n",
		peer, appended, localH)
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
	t := time.NewTicker(time.Duration(NetworkWatcherTime) * time.Second)
	defer t.Stop()

	// 일정 시간 마다 죽은 노드가 있는 지 검사하고, 죽은 노드는 주소 목록에서 제외함. 부트노드가 죽은 경우 재선춣함
	for range t.C {
		// log.Printf("[WATCHER] Conduct the Watcher's inspection")
		currentBoot := getBootAddr()
		if currentBoot == "" {
			continue
		}

		for _, addr := range peersSnapshot() {
			// 노드 별 상태 조사
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

// 체인 fork 현상 완화 루틴 (생존 노드 중 가장 체인 height 긴 체인으로 동기화)
func startChainWatcher() {
	t := time.NewTicker(time.Duration(ChainWatcherTime))
	defer t.Stop()

	for range t.C {

		// 이미 채굴 중이거나 메모리풀이 비어있지 않으면 수행하지 않음
		// 채굴이 기대되지 않는 상황에서 혼자 체인이 짧은 경우를 판별하기 위함
		if isMining.Load() || !pendingIsEmpty() {
			continue
		}

		// 가장 긴 노드의 주소, 높이, 최신블록해시
		bestPeer := ""
		bestHeight := -1
		bestHash := ""

		for _, p := range peersSnapshot() {
			st, ok := probeStatus(p)
			if !ok {
				continue
			}
			// 높이가 최대인 노드를 탐색하여 주소, 높이, 해시 저장
			if st.Height > bestHeight {
				bestHeight = st.Height
				bestHash = st.LastHash
				bestPeer = p
				continue
			}
			// height 같지만 hash가 다른 경우도 fork로 간주
			if st.Height == bestHeight && st.LastHash != bestHash {
				bestPeer = p
				bestHeight = st.Height
				bestHash = st.LastHash
			}
		}
		// 발견되지 않았다면 다음 주기까지 중단
		if bestPeer == "" {
			continue
		}

		// 로컬 상태
		chainMu.Lock()
		localH, _ := getLatestHeight()
		localLastHash := ""
		if localH >= 0 {
			blk, _ := getBlockByIndex(localH)
			localLastHash = blk.BlockHash
		}
		chainMu.Unlock()

		// 로컬 노드와 비교하여 체인 동기화 여부 결정
		needReset := false
		// 가장 긴 노드의 height가 로컬 노드보다 클 때
		if bestHeight > localH {
			needReset = true
		} else if bestHeight == localH && bestHash != localLastHash {
			// 가장 긴 노드의 height가 로컬 노드와 같지만, hash가 다를 때
			needReset = true
		}
		// 로컬 장부 리셋 후, bestPeer에게 체인을 동기화받음
		if needReset {
			log.Printf("[CHAIN-WATCHER] fork/outdated detected → reset + sync from %s", bestPeer)
			resetLocalDB()
			syncChain(bestPeer)
		}
	}
}
