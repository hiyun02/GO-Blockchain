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
	dbPath := getEnvDefault("Gov_DB_PATH", "blockchain_db")
	govID := getEnvDefault("Gov_ID", "Gov-A")
	addr := getEnvDefault("PORT", "5000")
	addr = ":" + addr

	boot = getEnvDefault("BOOTSTRAP_ADDR", "gov-boot:5000") // 부트노드 고정주소
	self = getEnvDefault("NODE_ADDR", "gov-node-00:5000")   // 이 노드의 외부접속 주소

	// 2) DB 초기화
	initDB(dbPath)
	defer closeDB()
	log.Printf("[시작] Gov LevelDB 경로: %s\n", dbPath)
	loadAllAnchorsAtBoot()
	loadHosRepresentativesAtBoot()
	log.Printf("[시작] 저장된 Hos 앵커를 복원했습니다: %s\n", dbPath)

	// 3) 체인 부팅 (제네시스 자동 생성/복구 포함)
	chain, err := newUpperChain(govID)
	if err != nil {
		log.Fatal("[시작][오류] Gov 체인 초기화 실패: ", err)
	}
	log.Printf("[시작] HotStuff 상위체인 준비 완료 (gov_id=%s)\n", govID)

	// 4) HTTP 라우팅 등록
	mux := http.NewServeMux()
	// 사용자와 상호작용을 위한 API 등록
	RegisterAPI(mux, chain)
	// 노드 간 통신 엔드포인트 등록
	//     - /addPeer : 기존 노드들이 신규 노드를 추가
	//	   - /hotstuff/propose : 리더의 Gov 블록 제안 수신
	//     - /hotstuff/vote : 단계별 투표 수신(리더)
	//     - /hotstuff/qc : Prepare/Pre-Commit/Commit QC 수신
	//	   - /register : 부트노드가 신규노드를 네트워크에 참여시킴
	//	   - /bootNotify : 부트노드 변경 수신
	//	   - /addAnchor : Hos 체인으로부터 Anchor 수신, 해당 Hos의 부트노드 주소를 다른 Gov 노드에 전파
	//	   - /hosBootNotify : Gov 부트노드로부터 전파된 Hos 부트노드 주소를 수신
	mux.HandleFunc("/addPeer", addPeer)
	mux.HandleFunc("/hotstuff/propose", handleHotStuffProposal)
	mux.HandleFunc("/hotstuff/vote", handleHotStuffVote)
	mux.HandleFunc("/hotstuff/qc", handleHotStuffQC)
	mux.HandleFunc("/register", registerPeer)
	mux.HandleFunc("/bootNotify", bootNotify)
	mux.HandleFunc("/addAnchor", addAnchor)
	mux.HandleFunc("/hosBootNotify", hosBootNotify)
	mux.HandleFunc("/consensus/validators", handleConsensusValidators)

	mux.Handle("/", http.FileServer(http.Dir("./static")))

	// 5) 앵커 서명을 위한 key pair 생성
	ensureKeyPair()
	initializeHotStuff()

	// 6) 서버 시작
	go func() {
		log.Println("[시작] Gov 노드 HTTP 서버가 실행 중입니다:", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatal(err)
		}
	}()

	// 7) 자동 부트스트랩
	//  부트노드가 아니라면 부트노드에 자신의 주소를 등록 -> 부트노드로부터 노드 주소 목록 받아 등록 -> 체인 동기화
	if boot != "" && self != "" && boot != self {
		// 내 공개키를 meta에서 가져옴
		myPubKey, ok := getMeta("meta_gov_pubkey")
		if !ok {
			log.Fatal("[BOOT] Public key not found in meta. Check ensureKeyPair.")
		}

		payload := map[string]string{
			"gov_id":  govID,
			"addr":    self,
			"pub_key": myPubKey,
		}
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
			log.Println("[BOOT] Now, This is Boot Node. skipping auto-join")
			isBoot.Store(true)
		} else {

			var reg struct {
				Peers    []string          `json:"peers"`
				PeerKeys map[string]string `json:"peer_keys"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
				log.Printf("[BOOT] decode peers failed: %v", err)
				return
			}
			log.Printf("[BOOT-JOIN] received %d peers from %s: %v", len(reg.Peers), boot, reg.Peers)

			// 수신된 명단을 순회하며 주소와 공개키를 함께 저장
			for addr, pubKey := range reg.PeerKeys {
				addPeerInternal(addr, pubKey)
			}

			// 초기 체인 동기화(부트노드로부터)
			go syncChain(boot)
			log.Printf("[BOOT] Chain Initialized by %s(boot node); peers=%v", boot, reg.Peers)
		}
	} else {
		log.Println("[BOOT] This is Boot Node, skipping auto-join")
		isBoot.Store(true)
	}

	// 7) 네트워크, HotStuff 합의, 체인 감시 루틴 실행
	go func() {
		log.Printf("[WATCHER] starting unified network watcher (%ds interval)", NetworkWatcherTime)
		startNetworkWatcher()
	}()

	go func() {
		log.Printf("[감시기] Gov HotStuff 합의 대기열 감시를 시작합니다. (주기=%d초)", ConsWatcherTime)
		startConsensusWatcher()
	}()
	//
	//go func() {
	//	log.Printf("[WATCHER] starting unified chain watcher (%ds interval)", ChainWatcherTime)
	//	startChainWatcher()
	//}()

	// 8) 메인 Go 루틴 유지
	select {}
}

func getEnvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
