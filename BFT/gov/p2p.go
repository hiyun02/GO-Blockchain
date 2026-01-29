package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// 노드 상태 구조체, /status API 호출 시 응답받는 JSON 구조
type nodeStatus struct {
	Addr     string   `json:"addr"`      // 노드 주소
	Height   int      `json:"height"`    // 블록 높이 (체인 진행 정도)
	IsBoot   bool     `json:"is_boot"`   // 부트노드 여부
	Peers    []string `json:"peers"`     // 연결된 피어 목록
	LastHash string   `json:"last_hash"` // 최신 블록의 해시
}

// 다른 노드 상태 조회
// 주어진 노드 주소(addr)에 HTTP GET 요청을 보내 /status API를 호출하고,
// 해당 노드의 현재 상태(nodeStatus)를 가져옴
func probeStatus(addr string) (nodeStatus, bool) {
	var s nodeStatus
	resp, err := http.Get("http://" + addr + "/status")
	if err != nil {
		return s, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return s, false
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return s, false
	}
	return s, true
}

// -----------------------------------------------------------------------------
// 블록 검증
// - 순서: index 증가, prevHash 일치
// - 머클루트/블록해시 재계산 일치
// - Gov_id 일치(제네시스와 동일 체인인지 확인)
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
	// 3) Gov_id 일치
	if prevBlk.GovID != newBlk.GovID {
		return fmt.Errorf("Gov_id mismatch: chain=%s new=%s", prevBlk.GovID, newBlk.GovID)
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
	var req struct {
		Addr   string `json:"addr"`
		PubKey string `json:"pub_key"` // 공개키 필드 추가
	}
	// 부트노드가 보낸 JSON 객체 파싱해
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid peer format", http.StatusBadRequest)
		return
	}
	if addPeerInternal(req.Addr, req.PubKey) { // 공개키 함께 전달
		w.Write([]byte("Peer added"))
	} else {
		w.Write([]byte("Peer exists"))
	}
}
func addPeerInternal(addr string, pubKey string) bool {
	if addr == "" || pubKey == "" {
		return false
	}
	peerMu.Lock()
	defer peerMu.Unlock()
	// 중복 방지
	if !addressYN(addr) {

		peers = append(peers, addr)

		pkMu.Lock()
		peerPubKeys[addr] = pubKey
		pkMu.Unlock()

		log.Printf("[P2P][ADD] peer added: %s (PubKey: %s...)", addr, pubKey[:10])
	} else {
		pkMu.Lock()
		peerPubKeys[addr] = pubKey
		pkMu.Unlock()
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

func addressYN(address string) bool {
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
//func startChainWatcher() {
//	t := time.NewTicker(time.Duration(ChainWatcherTime))
//	defer t.Stop()
//
//	for range t.C {
//
//		// 이미 채굴 중이거나 메모리풀이 비어있지 않으면 수행하지 않음
//		// 블록 생성이 기대되지 않는 상황에서 혼자 체인이 짧은 경우를 판별하기 위함
//		//if isMining.Load() || !pendingIsEmpty() {
//		//	continue
//		//}
//
//		// 가장 긴 노드의 주소, 높이, 최신블록해시
//		bestPeer := ""
//		bestHeight := -1
//		bestHash := ""
//
//		for _, p := range peersSnapshot() {
//			st, ok := probeStatus(p)
//			if !ok {
//				continue
//			}
//			// 높이가 최대인 노드를 탐색하여 주소, 높이, 해시 저장
//			if st.Height > bestHeight {
//				bestHeight = st.Height
//				bestHash = st.LastHash
//				bestPeer = p
//				continue
//			}
//			// height 같지만 hash가 다른 경우도 fork로 간주
//			if st.Height == bestHeight && st.LastHash != bestHash {
//				bestPeer = p
//				bestHeight = st.Height
//				bestHash = st.LastHash
//			}
//		}
//		// 발견되지 않았다면 다음 주기까지 중단
//		if bestPeer == "" {
//			continue
//		}
//
//		// 로컬 상태
//		chainMu.Lock()
//		localH, _ := getLatestHeight()
//		localLastHash := ""
//		if localH >= 0 {
//			blk, _ := getBlockByIndex(localH)
//			localLastHash = blk.BlockHash
//		}
//		chainMu.Unlock()
//
//		// 로컬 노드와 비교하여 체인 동기화 여부 결정
//		needReset := false
//		// 가장 긴 노드의 height가 로컬 노드보다 클 때
//		if bestHeight > localH {
//			needReset = true
//		} else if bestHeight == localH && bestHash != localLastHash {
//			// 가장 긴 노드의 height가 로컬 노드와 같지만, hash가 다를 때
//			needReset = true
//		}
//		// 로컬 장부 리셋 후, bestPeer에게 체인을 동기화받음
//		if needReset {
//			log.Printf("[CHAIN-WATCHER] fork/outdated detected → reset + sync from %s", bestPeer)
//			resetLocalDB()
//			syncChain(bestPeer)
//		}
//	}
