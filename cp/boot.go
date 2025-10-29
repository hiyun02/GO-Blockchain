package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 전역 상태 관리 변수
var (
	selfAddr   string       // 현재 노드 주소 NODE_ADDR (예: "cp-node-01:5000")
	startedAt  = time.Now() // 현재 노드 시작 시간
	isBoot     atomic.Bool  // 현재 노드가 부트노드인지 여부
	bootAddr   string       // 현재 네트워크 상의 부트노드 주소
	bootAddrMu sync.RWMutex // 부트노드 주소 접근 시 동시성 보호용 RW 잠금 객체
)

// ============================================
// 노드 상태 구조체
// ============================================
// /status API 호출 시 응답받는 JSON 구조
type nodeStatus struct {
	Addr   string   `json:"addr"`    // 노드 주소
	Height int      `json:"height"`  // 블록 높이 (체인 진행 정도)
	IsBoot bool     `json:"is_boot"` // 부트노드 여부
	Peers  []string `json:"peers"`   // 연결된 피어 목록
}

// ============================================
// 다른 노드 상태 조회
// ============================================
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

// ============================================
// 부트노드 선출 및 전환 (electAndSwitch)
// ============================================
// 네트워크 상의 모든 노드(peers + self)를 조사
// 1) 가장 높은 블록 높이를 가진 노드를 찾고
// 2) 동률이면 주소 사전순으로 가장 앞선 노드를 부트노드로 지정
//
// 현재 노드가 그 승자라면 → self를 부트노드로 승격
// 그렇지 않으면 → 해당 승자를 부트노드로 인식
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

func broadcastNewBoot(newBoot string) {
	for _, p := range peersSnapshot() {
		go func(dst string) {
			body, _ := json.Marshal(map[string]string{"addr": newBoot})
			_, err := http.Post("http://"+dst+"/boot", "application/json", strings.NewReader(string(body)))
			if err != nil {
				log.Printf("[BOOT] notify failed to %s: %v", dst, err)
			}
		}(p)
	}
}

// 새 부트노드 공지 수신(모든 노드 수행)
func bootNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct {
		Addr string `json:"addr"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Addr == "" {
		http.Error(w, "bad body", 400)
		return
	}
	// 검증: 실제 살아있는지 한 번 probe
	if _, ok := probeStatus(in.Addr); !ok {
		http.Error(w, "boot not reachable", 502)
		return
	}
	isBoot.Store(in.Addr == selfAddr)
	setBootAddr(in.Addr)
	w.WriteHeader(200)
}

func setBootAddr(a string) {
	bootAddrMu.Lock()
	bootAddr = a
	bootAddrMu.Unlock()
}
func getBootAddr() string {
	bootAddrMu.RLock()
	defer bootAddrMu.RUnlock()
	return bootAddr
}
