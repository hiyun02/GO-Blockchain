package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================
// 부트노드 기본 소스
// ============================================
// 부트노드가 신규 노드의 주소를 등록하고,
// 신규 노드에게 현재 피어 목록을 제공함
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
	// 이미 등록된 주소인지 검증
	already := checkAddress(req.Addr)

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

// 전역 상태 관리 변수
var (
	selfAddr   string       // 현재 노드 주소 NODE_ADDR (예: "cp-node-01:5000")
	startedAt  = time.Now() // 현재 노드 시작 시간
	isBoot     atomic.Bool  // 현재 노드가 부트노드인지 여부
	bootAddr   string       // 현재 네트워크 상의 부트노드 주소
	bootAddrMu sync.RWMutex // 부트노드 주소 접근 시 동시성 보호용 RW 잠금 객체
)

// 노드 상태 구조체, /status API 호출 시 응답받는 JSON 구조
type nodeStatus struct {
	Addr   string   `json:"addr"`    // 노드 주소
	Height int      `json:"height"`  // 블록 높이 (체인 진행 정도)
	IsBoot bool     `json:"is_boot"` // 부트노드 여부
	Peers  []string `json:"peers"`   // 연결된 피어 목록
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
// 1) 가장 높은 블록 높이를 가진 노드를 찾고
// 2) 동률이면 주소 사전순으로 가장 앞선 노드를 부트노드로 지정
// 현재 노드가 그 승자라면 -> self를 부트노드로 승격
// 그렇지 않으면 -> 해당 승자를 부트노드로 인식
func electAndSwitch() {
	// 후보: peers + self
	cand := peersSnapshot()
	cand = append(cand, selfAddr)

	// 상태 수집
	type info struct {
		ns nodeStatus
		ok bool
	}
	res := make([]info, len(cand))
	var wg sync.WaitGroup
	for i, a := range cand {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			ns, ok := probeStatus(addr)
			res[i] = info{ns, ok}
		}(i, a)
	}
	wg.Wait()

	// 생존만
	live := make([]nodeStatus, 0, len(res))
	for _, r := range res {
		if r.ok {
			live = append(live, r.ns)
		}
	}
	if len(live) == 0 {
		// 아무도 안 보이면 자기 자신을 부트로 승격
		isBoot.Store(true)
		setBootAddr(selfAddr)
		log.Printf("[BOOT] no live peers; self-promoted as boot: %s", selfAddr)
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

	if winner.Addr == selfAddr {
		isBoot.Store(true)
		setBootAddr(selfAddr)
		broadcastNewBoot(selfAddr)
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
	isBoot.Store(in.Addr == selfAddr)
	setBootAddr(in.Addr)

	// 성공 로그 출력
	if in.Addr == selfAddr {
		log.Printf("[BOOT] this node (%s) is now the bootnode", selfAddr)
	} else {
		log.Printf("[BOOT] updated bootnode: %s", in.Addr)
	}

	w.WriteHeader(200)
}

func startBootWatcher() {
	t := time.NewTicker(3 * time.Second)
	misses := 0
	for range t.C {
		ba := getBootAddr()
		if ba == "" {
			continue
		}
		// 내가 부트일 땐 헬스체크 스킵(필요시 self /status도 확인 가능)
		if ba == selfAddr && isBoot.Load() {
			misses = 0
			continue
		}

		if _, ok := probeStatus(ba); ok {
			misses = 0
			continue
		}
		misses++
		if misses >= 3 { // 3회 연속 실패 → 장애로 간주
			log.Printf("[BOOT] bootnode unreachable (%s), starting election", ba)
			electAndSwitch()
			misses = 0
		}
	}
}

func setBootAddr(addr string) {
	bootAddrMu.Lock()
	bootAddr = addr
	bootAddrMu.Unlock()
}
func getBootAddr() string {
	bootAddrMu.RLock()
	defer bootAddrMu.RUnlock()
	return bootAddr
}
