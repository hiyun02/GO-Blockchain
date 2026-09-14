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
	dbPath := getEnvDefault("Hos_DB_PATH", "blockchain_db")
	hosID := getEnvDefault("Hos_ID", "Hos-A")
	addr := getEnvDefault("PORT", "5000")
	addr = ":" + addr

	boot = getEnvDefault("BOOTSTRAP_ADDR", "hos-boot:5000")        // Hos체인 부트노드 주소
	self = getEnvDefault("NODE_ADDR", "hos-node-00:5000")          // 이 노드의 외부접속 주소
	govBoot = getEnvDefault("GOV_BOOTSTRAP_ADDR", "gov-boot:5000") // GOV체인 부트노드 주소

	// 2) DB 초기화
	initDB(dbPath)
	defer closeDB()
	log.Printf("[시작] LevelDB 경로: %s\n", dbPath)

	// 3) 체인 부팅 (제네시스 자동 생성/복구 포함)
	chain, err := newLowerChain(hosID)
	if err != nil {
		log.Fatal("[시작][오류] 하위 체인 초기화 실패: ", err)
	}
	log.Printf("[시작] HotStuff 하위 체인 준비 완료 (hos_id=%s)\n", hosID)

	// 4) HTTP 라우팅 등록
	mux := http.NewServeMux()
	// 사용자와 상호작용을 위한 API 등록
	RegisterAPI(mux, chain)
	// 노드 간 통신 엔드포인트 등록
	//     - /addPeer : 기존 노드들이 신규 노드를 추가
	//	   - /hotstuff/propose : 리더의 블록 제안 수신
	//	   - /hotstuff/vote : 단계별 투표 수신(리더)
	//	   - /hotstuff/qc : Prepare/Pre-Commit/Commit QC 수신
	//	   - /register : 부트노드 연결 및 네트워크 연결
	//	   - /bootNotify : 부트노드 변경 수신
	//	   - /getPublicKey : 공개키 반환
	//	   - /chgGovBoot : 신규 선출된 Gov 부트노드 주소를 Hos 부트노드가 수신
	//	   - /govBootNotify : Hos 부트노드로부터 전파된 Gov 부트노드 주소 수신
	mux.HandleFunc("/addPeer", addPeer)
	mux.HandleFunc("/hotstuff/propose", handleHotStuffProposal)
	mux.HandleFunc("/hotstuff/vote", handleHotStuffVote)
	mux.HandleFunc("/hotstuff/qc", handleHotStuffQC)
	mux.HandleFunc("/register", registerPeer)
	mux.HandleFunc("/bootNotify", bootNotify)
	mux.HandleFunc("/getPublicKey", getPublicKey)
	mux.HandleFunc("/chgGovBoot", chgGovBoot)
	mux.HandleFunc("/govBootNotify", govBootNotify)

	mux.Handle("/", http.FileServer(http.Dir("./static")))

	// 5) 앵커 서명을 위한 key pair 생성
	ensureKeyPair()
	initializeHotStuff()

	// 6) 서버 시작 (REST 요청 수신 가능한 상태로 돌입)
	go func() {
		log.Println("[시작] 노드 HTTP 서버가 실행 중입니다:", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatal(err)
		}
	}()

	// 7) 자동 부트스트랩
	//  부트노드가 아니라면 부트노드에 자신의 주소를 등록 -> 부트노드로부터 노드 주소 목록 받아 등록 -> 체인 동기화
	if boot != "" && self != "" && boot != self {

		// 내 공개키를 meta에서 가져옴
		myPubKey, ok := getMeta("meta_hos_pubkey")
		if !ok {
			log.Fatal("[부트][오류] 메타데이터에서 공개키를 찾을 수 없습니다.")
		}

		payload := map[string]string{
			"hos_id":  hosID,
			"addr":    self,
			"pub_key": myPubKey,
		}
		b, _ := json.Marshal(payload)

		resp, err := http.Post("http://"+boot+"/register", "application/json", strings.NewReader(string(b)))
		if err != nil {
			log.Printf("[부트][오류] 부트노드 등록 요청 실패: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("[부트][경고] 등록 거부: 상태=%d 응답=%s", resp.StatusCode, string(body))
			log.Println("[부트] 현재 노드를 부트노드로 사용하며 자동 참여를 건너뜁니다.")
			isBoot.Store(true)
		} else {

			var reg struct {
				Peers    []string          `json:"peers"`
				PeerKeys map[string]string `json:"peer_keys"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
				log.Printf("[부트][오류] 피어 목록 해석 실패: %v", err)
				return
			}
			log.Printf("[부트][참여] %s에서 피어 %d개를 받았습니다: %v", boot, len(reg.Peers), reg.Peers)

			// 수신된 명단을 순회하며 주소와 공개키를 함께 저장
			for addr, pubKey := range reg.PeerKeys {
				addPeerInternal(addr, pubKey)
			}

			// 초기 체인 동기화(부트노드로부터)
			go syncChain(boot)
			log.Printf("[부트] %s에서 체인 동기화를 시작했습니다. 피어=%v", boot, reg.Peers)
		}
	} else {
		log.Println("[부트] 현재 노드가 부트노드이므로 자동 참여를 건너뜁니다.")
		isBoot.Store(true)
	}
	// 8) 네트워크, HotStuff 합의, 체인 감시 루틴 실행
	go func() {
		log.Printf("[감시기] 네트워크 감시를 시작합니다. (주기=%d초)", NetworkWatcherTime)
		startNetworkWatcher()
	}()
	go func() {
		log.Printf("[감시기] HotStuff 합의 대기열 감시를 시작합니다. (주기=%d초)", ConsWatcherTime)
		startConsensusWatcher()
	}()
	//go func() {
	//	log.Printf("[WATCHER] starting unified chain watcher (%ds interval)", ChainWatcherTime)
	//	startChainWatcher()
	//}()

	// 9) 메인 Go 루틴 유지
	select {}
}

func getEnvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
