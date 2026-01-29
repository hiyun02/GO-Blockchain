package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
)

// ============================================
// 부트노드 기본 소스
// ============================================
// 부트노드가 신규 노드의 주소를 등록하고,
// 신규 노드에게 현재 피어 목록을 제공함
type registerReq struct {
	HosID  string `json:"hos_id"`
	Addr   string `json:"addr"`    // 신규 노드의 접근 주소 (예: "host:port")
	PubKey string `json:"pub_key"` // 신규 노드의 공개키
}
type registerResp struct {
	Peers    []string          `json:"peers"`
	PeerKeys map[string]string `json:"peer_keys"`
}

// 신규노드가 네트워크 진입 시 부트노드에게 다른 노드들의 주소를 제공받기 위한 함수
func registerPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Addr == "" || req.PubKey == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	// 체인 ID 확인
	blk0, err := getBlockByIndex(0)
	if err != nil || blk0.HosID != req.HosID {
		http.Error(w, "hos_id mismatch", http.StatusForbidden)
		log.Printf("[BOOT] Join denied: hos_id mismatch (%s)", req.HosID)
		return
	}

	// 신규 노드 등록
	peerMu.Lock()
	pkMu.Lock()
	// 등록된 주소가 아니라면 추가
	if !addressYN(req.Addr) {
		peers = append(peers, req.Addr)
		log.Printf("[P2P][REGISTER] new peer joined: %s (hos_id=%s) | total=%d", req.Addr, req.HosID, len(peers))
	}
	peerPubKeys[req.Addr] = req.PubKey

	outPeers := make([]string, 0)
	outKeys := make(map[string]string)

	// 부트노드 자신의 정보도 포함시킴
	myPubKey, _ := getMeta("meta_hos_pubkey")
	outPeers = append(outPeers, self)
	outKeys[self] = myPubKey

	for addr, key := range peerPubKeys {
		if addr != req.Addr {
			outPeers = append(outPeers, addr)
			outKeys[addr] = key
		}
	}
	pkMu.Unlock()
	peerMu.Unlock()

	// 신규 노드는 peerAliveMap에 초기 상태 초기화
	markAlive(req.Addr, true)

	// 기존 피어들에게 새로운 노드의 주소와 공개키를 넘김
	go notifyNewPeerWithKey(req.Addr, req.PubKey)

	// 현재까지 등록된 모든 노드의 공개키 맵을 반환
	resp := registerResp{
		Peers:    outPeers,
		PeerKeys: outKeys,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// 기존 노드들에게 신규 노드의 주소와 공개키를 전파
func notifyNewPeerWithKey(newAddr, newPubKey string) {
	peerList := peersSnapshot()
	for _, p := range peerList {
		if p == newAddr || p == self {
			continue
		}
		go func(dst string) {
			body, _ := json.Marshal(map[string]string{
				"addr":    newAddr,
				"pub_key": newPubKey,
			})
			_, err := http.Post("http://"+dst+"/addPeer", "application/json", bytes.NewReader(body))
			if err != nil {
				log.Printf("[BOOT] Failed to notify %s about new peer", dst)
			}
		}(p)
	}
}

// ============================================
// 부트노드 상태 관리 소스
// ============================================

// 부트노드 선출 및 전환
// 네트워크 상의 모든 노드(peers + self)를 조사
// 1) 가장 높은 블록 높이를 가진 노드를 찾음
// 2) 동률이면 주소 사전순으로 가장 앞선 노드를 부트노드로 지정
// 현재 노드가 그 승자라면 => self를 부트노드로 승격
// 그렇지 않으면 => 해당 승자를 부트노드로 인식
func electAndSwitch() {
	// 후보: peers + self
	cand := peersSnapshot()
	cand = append(cand, self)

	// 상태 수집
	type info struct {
		ns nodeStatus
		ok bool
	}
	// 각 후보 노드(cand)의 상태를 병렬로 수집
	res := make([]info, len(cand)) // 후보 노드 개수만큼 info 구조체 슬라이스 미리 생성
	var wg sync.WaitGroup          // 모든 고루틴이 끝날 때까지 대기하기 위한 동기화 객체

	for i, a := range cand {
		wg.Add(1) // go루틴 하나 실행할 때마다 할 일 +1
		go func(i int, addr string) {
			defer wg.Done() // 이 go루틴이 끝나면 할 일 -1

			// 각 노드의 /status API를 호출하여 (Addr, Height, IsBoot, Peers) 상태를 조회
			ns, ok := probeStatus(addr)

			// 병렬로 실행되지만, i는 고정되어 있으므로
			// 결과를 res[i]에 정확히 저장할 수 있음 (데이터 경합 없음)
			res[i] = info{ns, ok}
		}(i, a)
	}

	// 위 for 루프 안의 모든 고루틴이 끝날 때까지 대기
	// 모든 /status 요청이 완료될 때까지 블록
	wg.Wait()

	// 수집된 결과를 바탕으로 살아있는 노드(live)만 선별
	live := make([]nodeStatus, 0, len(res))
	for _, r := range res {
		if r.ok {
			live = append(live, r.ns)
			markAlive(r.ns.Addr, true) // 노드 상태 true로 기록
		} else {
			markAlive(r.ns.Addr, false) // 노드 상태 false로 기록
		}
	}
	// 살아있는 노드가 없다면 자기 자신을 부트로 승격
	if len(live) == 0 {
		isBoot.Store(true)
		setBootAddr(self)
		log.Printf("[BOOT] no live peers; self-promoted as boot: %s", self)
		return
	}

	// 부트노드 선정 기준: 높이 최댓값, 동률이면 주소 사전순 최소
	winner := live[0]
	for _, x := range live[1:] {
		if x.Height > winner.Height ||
			(x.Height == winner.Height && x.Addr < winner.Addr) {
			winner = x
		}
	}

	if winner.Addr == self {
		isBoot.Store(true)
		setBootAddr(self)
		broadcastNewBoot(self)
		log.Printf("[BOOT] elected as new bootnode (height=%d)", winner.Height)
	} else {
		isBoot.Store(false)
		setBootAddr(winner.Addr)
		log.Printf("[BOOT] new bootnode recognized: %s (height=%d)", winner.Addr, winner.Height)
	}
}

// 자신이 새 부트노드로 선출되었을 때 다른 모든 피어들에게 전파
func broadcastNewBoot(newBoot string) {
	for _, p := range peersSnapshot() {
		go func(dst string) {
			body, _ := json.Marshal(map[string]string{"addr": newBoot})
			_, err := http.Post("http://"+dst+"/bootNotify", "application/json", strings.NewReader(string(body)))
			if err != nil {
				log.Printf("[BOOT] notify failed to %s: %v", dst, err)
			}
		}(p)
	}
}

// 부트노드 변경 수신(모든 노드 수행)
func bootNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	// 응답 파싱할 구조체
	var in struct {
		Addr string `json:"addr"`
	}
	// 요청 본문이 유효한 JSON이 아니거나 addr 필드가 비어 있다면 잘못된 요청으로 간주
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Addr == "" {
		http.Error(w, "bad body", 400)
		return
	}
	// 전달받은 부트노드 주소가 실제로 살아있는지 검증
	if _, ok := probeStatus(in.Addr); !ok {
		http.Error(w, "boot not reachable", 502)
		log.Printf("[BOOT] received new boot addr (%s) but not reachable", in.Addr)
		return
	}

	// 상태 반영
	isBoot.Store(in.Addr == self)
	setBootAddr(in.Addr)

	// 성공 로그 출력
	if in.Addr == self {
		log.Printf("[BOOT] this node (%s) is now the bootnode", self)
	} else {
		log.Printf("[BOOT] updated bootnode: %s", in.Addr)
	}
	w.WriteHeader(200)
}

// Hos 부트노드가 Gov 부트노드 변경 수신
// POST /chgGovBoot
func chgGovBoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	// 응답 파싱할 구조체
	var in struct {
		GovAddr string `json:"addr"`
	}
	// 요청 본문이 유효한 JSON이 아니거나 addr 필드가 비어 있다면 잘못된 요청으로 간주
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.GovAddr == "" {
		http.Error(w, "bad body", 400)
		return
	}
	// 전달받은 부트노드 주소가 실제로 살아있는지 검증
	if _, ok := probeStatus(in.GovAddr); !ok {
		http.Error(w, "boot not reachable", 502)
		log.Printf("[BOOT] received new Gov Boot addr (%s) but not reachable", in.GovAddr)
		return
	}

	// 전역변수에 반영 및 전파
	setGovBoot(in.GovAddr)
	log.Printf("[BOOT] this node (%s) is new Gov bootnode now", in.GovAddr)
	broadcastNewGovBoot(in.GovAddr)
	w.WriteHeader(200)
}

// Gov 부트노드 주소를 수신한 후 다른 모든 피어들에게 전파
func broadcastNewGovBoot(govBoot string) {
	for _, p := range peersSnapshot() {
		go func(dst string) {
			log.Printf("[BOOT][Gov] HosBOOT is now sending New GovBootNode's Addr to : %s", dst)
			body, _ := json.Marshal(map[string]string{"addr": govBoot})
			_, err := http.Post("http://"+dst+"/govBootNotify", "application/json", strings.NewReader(string(body)))
			if err != nil {
				log.Printf("[BOOT] notify failed to %s: %v", dst, err)
			}
		}(p)
	}
}

// 부트노드 변경 수신(모든 노드 수행)
// POST : /govBootNotify
func govBootNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	// 응답 파싱할 구조체
	var in struct {
		GovAddr string `json:"addr"`
	}
	// 요청 본문이 유효한 JSON이 아니거나 addr 필드가 비어 있다면 잘못된 요청으로 간주
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.GovAddr == "" {
		http.Error(w, "bad body", 400)
		return
	}
	// 전달받은 gov 부트노드 주소가 실제로 살아있는지 검증
	if _, ok := probeStatus(in.GovAddr); !ok {
		http.Error(w, "boot not reachable", 502)
		log.Printf("[BOOT] received new boot addr (%s) but not reachable", in.GovAddr)
		return
	}

	// 전역변수에 반영
	setGovBoot(in.GovAddr)
	// 성공 로그 출력
	log.Printf("[BOOT] this node (%s) is new Gov bootnode now", in.GovAddr)
	w.WriteHeader(200)
}

func setBootAddr(addr string) {
	bootAddrMu.Lock()
	boot = addr
	bootAddrMu.Unlock()
}
func getBootAddr() string {
	bootAddrMu.RLock()
	defer bootAddrMu.RUnlock()
	return boot
}
func setGovBoot(addr string) {
	govBootMu.Lock()
	govBoot = addr
	govBootMu.Unlock()
}
func getGovBoot() string {
	govBootMu.RLock()
	defer govBootMu.RUnlock()
	return govBoot
}
