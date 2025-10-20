//package cp
//
//import (
//	"log"
//	"net/http"
//)
//
//func main() {
//	// 1. DB 초기화
//	initDB("blockchain_db")
//	defer closeDB()
//
//	// 2. 제네시스 블록 생성 (DB가 비었을 때만)
//	if len(blockchain) == 0 {
//		genesis := createGenesisBlock()
//		blockchain = append(blockchain, genesis)
//		saveBlockToDB(genesis)
//		updateHashTable(genesis)
//		log.Println("[NODE] Genesis block created")
//	}
//
//	// 3. API + P2P 서버 실행
//	http.HandleFunc("/chain", getBlockchain)
//	http.HandleFunc("/mine", mineBlock)
//	http.HandleFunc("/peers", getPeers)
//	http.HandleFunc("/addPeer", addPeer)
//	http.HandleFunc("/receive", receiveBlock)
//	http.HandleFunc("/block/index", getBlockByIndexAPI)
//	http.HandleFunc("/block/hash", getBlockByHashAPI)
//	http.HandleFunc("/block/payload", getBlockByContentAPI)
//
//	log.Println("[NODE] Running on port 5000...")
//	log.Fatal(http.ListenAndServe(":5000", nil))
//}
