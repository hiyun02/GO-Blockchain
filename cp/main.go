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

	boot := getEnvDefault("BOOTSTRAP_ADDR", "") // 부트노드 고정주소
	self := getEnvDefault("NODE_ADDR", "")      // 이 노드의 외부접속 주소

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
	// CP 체인 API 등록(확정형): /content/add, /block/finalize, /block/root, /blocks, /block/index, /block/hash, /search, /proof
	RegisterAPI(mux, chain)
	// P2P 엔드포인트 등록
	//     - /peers : 피어 목록 조회
	//     - /addPeer : 피어 추가
	//     - /receive : 다른 노드가 보낸 확정 블록 수신
	//	   - /register : 부트노드 연결 및 네트워크 연결
	mux.HandleFunc("/peers", getPeers)
	mux.HandleFunc("/addPeer", addPeer)
	mux.HandleFunc("/receive", receiveBlock)
	mux.HandleFunc("/register", registerPeer)

	// 5) 서버 시작 (고루틴으로 실행해 메인 Go 루틴이 계속 진행되도록)
	go func() {
		log.Println("[START] NODE Running on", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatal(err)
		}
	}()

	// 6) 자동 부트스트랩: 부트노드에 등록 -> 피어 목록 받아 로컬 등록 -> 초기 동기화
	//    (부트노드 자신은 BOOTSTRAP_ADDR를 비우거나 자기 주소로 두고, 여기서 스킵돼도 무방)
	if boot != "" && self != "" {
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

			// 이전: http://self/addPeer 로 POST
			// 변경: 같은 프로세스이므로 직접 추가 (레이스/이름 이슈 제거)
			for _, addr := range reg.Peers {
				addPeerInternal(addr)
			}

			// 초기 체인 동기화(부트노드로부터)
			go syncChain(boot)
			log.Printf("[BOOT] joined via %s; peers=%v", boot, reg.Peers)
		}()
	} else {
		log.Println("[BOOT] skipping auto-join (BOOTSTRAP_ADDR or NODE_ADDR empty)")
	}

	// 7) 메인 Go 루틴 유지
	select {}
}

func getEnvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
