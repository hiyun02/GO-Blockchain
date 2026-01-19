// api.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// JSON 헬퍼
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// main.go에서 mux와 LowerChain을 넘겨받아 API 핸들 등록
func RegisterAPI(mux *http.ServeMux, chain *LowerChain) {

	// 최신 머클루트 (Gov 앵커용)
	// GET /block/root
	mux.HandleFunc("/block/root", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		root := getLatestRoot() // storage의 getLatestRoot 사용
		writeJSON(w, http.StatusOK, map[string]string{"root": root})
	})

	// 블록 조회: 인덱스
	// GET /block/index?id=<int>
	mux.HandleFunc("/block/index", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query().Get("id")
		if q == "" {
			http.Error(w, "id parameter required", http.StatusBadRequest)
			return
		}
		idx, err := strconv.Atoi(q)
		if err != nil {
			http.Error(w, "id must be integer", http.StatusBadRequest)
			return
		}
		blk, err := getBlockByIndex(idx)
		if err != nil {
			http.Error(w, "block not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, blk)
	})

	// 블록 조회: 해시
	// GET /block/hash?value=<hash>
	mux.HandleFunc("/block/hash", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		hash := r.URL.Query().Get("value")
		if hash == "" {
			http.Error(w, "value parameter required", http.StatusBadRequest)
			return
		}
		blk, err := getBlockByHash(hash)
		if err != nil {
			http.Error(w, "block not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, blk)
	})

	// 키워드로 레코드 검색(정확 일치: cid/pc/info_cCode)
	// GET /search?value=<keyword>
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		kw := r.URL.Query().Get("value")
		if kw == "" {
			http.Error(w, "value parameter required", http.StatusBadRequest)
			return
		}
		logInfo("search query keyword: %s", kw)
		// 검색 수행
		results, err := searchClinic(kw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		logInfo("query response's length: %s", len(results))
		// 결과 반환
		writeJSON(w, http.StatusOK, results)
	})

	// 전체 장부 조회 (페이지네이션)
	// GET /blocks?offset=<int>&limit=<int>
	mux.HandleFunc("/blocks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		blocks, total, err := listBlocksPaginated(offset, limit)
		if err != nil {
			http.Error(w, fmt.Sprintf("list blocks error: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"total":      total,
			"offset":     offset,
			"limit":      limit,
			"items":      blocks,
			"difficulty": GlobalDifficulty,
		})
	})

	// 노드 상태 확인
	// GET /status : 헬스/높이/주소 리턴 (부트노드 선정에 사용)
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		chainMu.Lock()
		h, _ := getLatestHeight()
		lastHash := ""
		lb, err := getBlockByIndex(h)
		if err != nil {
			log.Printf("[P2P] Block Hash Not Found")
		} else {
			lastHash = lb.BlockHash
		}
		chainMu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"addr":       self,
			"height":     h,
			"is_boot":    isBoot.Load(),
			"bootAddr":   boot,
			"started_at": startedAt.Format(time.RFC3339),
			"peers":      peersSnapshot(),
			"difficulty": GlobalDifficulty,
			"Gov_boot":   getGovBoot(),
			"last_hash":  lastHash,
		})
	})

	// 현재 노드가 알고 있는 피어 리스트 반환
	// GET /peers
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(peersSnapshot()) // 비어있어도 "[]" 반환
	})

	// 채굴 요청을 받아 메모리풀에 저장시킴
	// POST /mine
	mux.HandleFunc("/mine", func(w http.ResponseWriter, r *http.Request) {
		var rec []ClinicRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "invalid Clinic record", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		appendPending(rec) // 데이터 저장

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "Mining Request Submitted",
			"count":  len(rec),
		})
	})
}
