// main.go
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	// 1) 설정값 (환경변수 혹은 기본값 사용)
	dbPath := getEnvDefault("CP_DB_PATH", "blockchain_db")
	cpID := getEnvDefault("CP_ID", "CP-A")
	addr := getEnvDefault("PORT", "5000")
	addr = ":" + addr

	boot = getEnvDefault("BOOTSTRAP_ADDR", "cp-boot:5000") // 부트노드 고정주소
	self = getEnvDefault("NODE_ADDR", "cp-node-00:5000")   // 이 노드의 외부접속 주소

	// 2) DB 초기화
	initDB(dbPath)
	defer closeDB()
	log.Printf("[START] LevelDB: %s\n", dbPath)

	// 3) 체인 부팅 (제네시스 자동 생성/복구 포함)
	chain, err := newLowerChain(cpID)
	if err != nil {
		log.Fatal("[START] chain init error: ", err)
	}
	log.Printf("[START] LowerChain ready (cp_id=%s)\n", cpID)

	// 4) HTTP 라우팅 등록
	mux := http.NewServeMux()
	// 사용자와 상호작용을 위한 API 등록
	RegisterAPI(mux, chain)
	// P2P 엔드포인트 등록
	//     - /addPeer : 기존 노드들이 신규 노드를 추가
	//     - /receive : 다른 노드가 보낸 확정 블록 수신
	//	   - /register : 부트노드 연결 및 네트워크 연결
	//	   - /bootNotify : 부트노드 변경 수신
	mux.HandleFunc("/addPeer", addPeer)
	mux.HandleFunc("/receive", receive)
	mux.HandleFunc("/register", registerPeer)
	mux.HandleFunc("/bootNotify", bootNotify)

	// 5) 서버 시작 (고루틴으로 실행해 메인 Go 루틴이 계속 진행되도록)
	go func() {
		log.Println("[START] NODE Running on", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatal(err)
		}
	}()

	// 6) 자동 부트스트랩
	//  부트노드가 아니라면 부트노드에 자신의 주소를 등록 -> 부트노드로부터 노드 주소 목록 받아 등록 -> 체인 동기화
	if boot != "" && self != "" && boot != self {
		go func() {
			payload := map[string]string{"addr": self, "cp_id": cpID}
			b, _ := json.Marshal(payload)

			resp, err := http.Post("http://"+boot+"/register", "application/json", strings.NewReader(string(b)))
			if err != nil {
				log.Printf("[BOOT] register failed: %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				log.Printf("[BOOT] register failed : status=%d body=%s", resp.StatusCode, string(body))
				return
			}

			var reg struct {
				Peers []string `json:"peers"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
				log.Printf("[BOOT] decode peers failed: %v", err)
				return
			}
			log.Printf("[BOOT-JOIN] received %d peers from %s: %v", len(reg.Peers), boot, reg.Peers)

			// 부트노드와 부트노드에게 받은 노드 주소들을 peers 객체에 추가함
			addPeerInternal(boot)
			for _, addr := range reg.Peers {
				addPeerInternal(addr)
			}

			// 초기 체인 동기화(부트노드로부터)
			go syncChain(boot)
			log.Printf("[BOOT] Chain Initialized by %s(boot node); peers=%v", boot, reg.Peers)
		}()
	} else {
		log.Println("[BOOT] This is Boot Node, skipping auto-join")
		isBoot.Store(true)
	}

	// 7) 네트워크 감시 루틴 실행
	// 네트워크 내 모든 노드를 주기적으로 검사하고,
	// 응답이 없는 노드를 제거하며, 만약 부트노드가 죽은 경우 새로 선출하는 감시 루프
	go func() {
		log.Println("[WATCHER] starting unified network watcher (10s interval)")
		startNetworkWatcher()
	}()

	// 8) 메인 Go 루틴 유지
	select {}
}

func getEnvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
