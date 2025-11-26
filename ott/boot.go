package main

import (
	"encoding/json"
	"io"
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
	Addr  string `json:"addr"` // "host:port" 또는 "컨테이너명:포트"
	OttID string `json:"ott_id"`
}
type registerResp struct {
	Peers []string `json:"peers"`
}

// 신규노드가 네트워크 진입 시 부트노드가 다른 노드들의 주소를 제공하는 함수
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

	// 체인 정체성 확인: 제네시스 ott_id와 일치해야 가입 허용
	blk0, err := getBlockByIndex(0)
	if err != nil || blk0.OttID != req.OttID {
		http.Error(w, "ott_id mismatch", http.StatusForbidden)
		return
	}

	// 부트노드 로컬 peers에 추가
	peerMu.Lock() // 동시 접근 막음
	// 이미 등록된 주소인지 검증
	already := checkAddress(req.Addr)

	// 등록된 주소가 아니라면 추가
	if !already {
		peers = append(peers, req.Addr)
		log.Printf("[P2P][REGISTER] new peer joined: %s (ott_id=%s) | total=%d", req.Addr, req.OttID, len(peers))
	} else {
		log.Printf("[P2P][REGISTER] peer already exists: %s", req.Addr)
	}

	// 신규 노드는 peerAliveMap에 초기 상태 초기화
	markAlive(req.Addr, true)

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
		log.Printf("[P2P][REGISTER] notifying %d peers about %s", len(others), newPeer)
		b, _ := json.Marshal(newPeer)
		for _, op := range others {
			resp, err := http.Post("http://"+op+"/addPeer", "application/json", strings.NewReader(string(b)))
			if err != nil {
				log.Printf("[P2P][REGISTER] notify failed to %s: %v", op, err)
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			log.Printf("[P2P][REGISTER] notified %s (status=%d)", op, resp.StatusCode)
		}
	}(req.Addr, out)

	// 신규 노드에게 현재 피어 목록을 응답
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(registerResp{Peers: out})
}

// ============================================
// 부트노드 상태 관리 소스
// ============================================

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

// 부트노드 선출 및 전환
// 네트워크 상의 모든 노드(peers + self)를 조사
// 1) 가장 높은 블록 높이를 가진 노드를 찾음
// 2) 동률이면 주소 사전순으로 가장 앞선 노드를 부트노드로 지정
// 3) 선출된 부트노드는 다른 ott노드들에게 자신의 주소를 전파
// 4) 선출된 부트노드는 CP 부트노드들에게 자신의 주소를 전파
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
	// 자신이 승자노드가 된 경우, 다른 ott 노드들과 cp 부트노드들에게 자신의 주소 전파
	if winner.Addr == self {
		isBoot.Store(true)
		setBootAddr(self)
		broadcastNewBoot(self) // 다른 ott 노드들에게 전파
		broadcastNewBootToCp(self)
		log.Printf("[BOOT] elected as new bootnode (height=%d)", winner.Height)
	} else {
		isBoot.Store(false)
		setBootAddr(winner.Addr)
		log.Printf("[BOOT] new bootnode recognized: %s (height=%d)", winner.Addr, winner.Height)
	}
}

// 자신이 새 부트노드로 선출되었을 때, 다른 모든 피어들에게 전파
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
// POST : /bootNotify
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

// 자신이 새 OTT 부트노드로 선출되었을 때, 기존에 등록된 모든 CP 부트노드들에게 전파
func broadcastNewBootToCp(newBoot string) {
	for cpID, cpBoot := range cpBootMap {
		go func(id, dst string) {
			log.Printf("[BOOT][ToCP] New OTT Boot Node's Addr is now sending to : %s", dst)
			body, _ := json.Marshal(map[string]string{"ott_boot": newBoot})
			_, err := http.Post("http://"+dst+"/chgOttBoot", "application/json", strings.NewReader(string(body)))
			if err != nil {
				log.Printf("[BOOT] notify failed to %s: %v", dst, err)
			}
		}(cpID, cpBoot)
	}
	log.Printf("[BOOT][OTTtoCP] New OTT Boot Node's Addr was sent to Cp Boot Nodes")
}

// 신규 CP체인의 부트노드가 앵커를 제출했을 때, 이를 저장한 후 다른 ott 노드에게 전파
func broadcastNewCpBoot(cpID, cpBoot string) {
	// 부트노드 자신에게 신규 cp 부트노드 주소 저장
	logInfo("[BOOT] Store newCpBoot to CpBootMap")
	setCpBootAddr(cpID, cpBoot)
	// 나머지 ott 노드들에게 cp 부트노드 주소 전파
	for _, peer := range peersSnapshot() {
		go func(dst string) {
			body, _ := json.Marshal(map[string]string{"cp_id": cpID, "cp_boot": cpBoot})
			logInfo("[BOOT] notify new cpBoot to %s", dst)
			_, err := http.Post("http://"+dst+"/cpBootNotify", "application/json", strings.NewReader(string(body)))
			if err != nil {
				log.Printf("[BOOT] notify failed to %s: %v", dst, err)
			}
		}(peer)
	}
	log.Printf("[BOOT][NETWORK] Complete Broadcasting New CP Boot : %s", cpBoot)
}

// 신규 CP의 CpID 및 부트노드 주소 수신(ott 모든 노드 수행)
// POST : /cpBootNotify
func cpBootNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	// 응답 파싱할 구조체
	var in struct {
		CpID   string `json:"cp_id"`
		CpBoot string `json:"cp_boot"`
	}
	// 요청 본문이 유효한 JSON이 아니거나 주소 필드가 비어 있다면 잘못된 요청으로 간주
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.CpBoot == "" {
		http.Error(w, "bad body", 400)
		return
	}
	// 전달받은 부트노드 주소가 실제로 살아있는지 검증
	if _, ok := probeStatus(in.CpBoot); !ok {
		http.Error(w, "boot not reachable", 502)
		log.Printf("[BOOT] received new boot addr (%s) but not reachable", in.CpBoot)
		return
	}
	// CP 체인의 ID와 부트노드 주소 저장
	setCpBootAddr(in.CpID, in.CpBoot)
	// 성공 로그 출력
	log.Printf("[BOOT] Successfully received cpBoot: %s : %s to CpBootMap )", in.CpID, in.CpBoot)
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

func setCpBootAddr(cpID, addr string) {
	cpBootMapMu.Lock()
	cpBootMap[cpID] = addr
	cpBootMapMu.Unlock()
	logInfo("[BOOT] set new CpBoot addr to CpBootMap: %s", addr)
}
func getCpBootAddr(cpID string) string {
	cpBootMapMu.RLock()
	defer cpBootMapMu.RUnlock()
	return cpBootMap[cpID]
}
