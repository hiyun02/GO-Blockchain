// main.go
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	// 1) 설정값 (환경변수 → 기본값)
	dbPath := getenvDefault("CP_DB_PATH", "blockchain_db")
	cpID := getenvDefault("CP_ID", "CP-A")
	addr := getenvDefault("PORT", "5000")
	addr = ":" + addr

	// 2) DB 초기화
	initDB(dbPath)
	defer closeDB()
	log.Printf("[BOOT] LevelDB: %s\n", dbPath)

	// 3) 체인 부팅 (제네시스 자동 생성/복구 포함)
	chain, err := newLowerChain(cpID)
	if err != nil {
		log.Fatal("[BOOT] chain init error: ", err)
	}
	log.Printf("[BOOT] LowerChain ready (cp_id=%s)\n", cpID)

	// 4) HTTP 라우팅 등록
	mux := http.NewServeMux()

	// (A) CP 체인 API (확정형): /content/add, /block/finalize, /block/root, /blocks, /block/index, /block/hash, /search, /proof
	RegisterAPI(mux, chain)

	// (B) P2P 관련 엔드포인트 유지
	//     - /peers : 피어 목록 조회
	//     - /addPeer : 피어 추가
	//     - /receive : 다른 노드가 보낸 확정 블록 수신
	mux.HandleFunc("/peers", getPeers)
	mux.HandleFunc("/addPeer", addPeer)
	mux.HandleFunc("/receive", receiveBlock)

	// (C) (선택) 구버전 호환 라우트 유지하고 싶으면 주석 해제
	// mux.HandleFunc("/block/payload", getBlockByContentAPI) // = /search

	// 5) 서버 시작
	log.Println("[NODE] Running on", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
