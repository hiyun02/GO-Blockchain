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

	// 최신 머클루트 (OTT 앵커용)
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

	// 키워드로 블록 검색(정확 일치: cid/fp/info_title)
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
		blk, err := getBlockByContent(kw)
		if err != nil {
			http.Error(w, "block not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, blk)
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
			"total":  total,
			"offset": offset,
			"limit":  limit,
			"items":  blocks,
		})
	})

	// 머클 증명 제공 (색인 기반 즉시 접근)
	// GET /proof?cid=<content_id>
	mux.HandleFunc("/proof", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cid := r.URL.Query().Get("cid")
		if cid == "" {
			http.Error(w, "missing query param: cid", http.StatusBadRequest)
			return
		}
		rec, blk, proof, ok := chain.getContentWithProofIndexed(cid)
		if !ok {
			http.Error(w, "content not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"record": rec,
			"block":  blk,
			"proof":  proof, // [][2]string { siblingHex, "L"/"R" }
		})
	})

	// 노드 상태 확인
	// GET /status : 헬스/높이/주소 리턴 (부트노드 선정에 사용)
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		h, _ := getLatestHeight()
		writeJSON(w, http.StatusOK, map[string]any{
			"addr":       self,
			"height":     h,
			"is_boot":    isBoot.Load(),
			"bootAddr":   boot,
			"started_at": startedAt.Format(time.RFC3339),
			"peers":      peersSnapshot(),
		})
	})

	// 현재 노드가 알고 있는 피어 리스트 반환
	// GET /peers
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(peersSnapshot()) // 비어있어도 "[]" 반환
	})

	// 최초 채굴 요청을 받아 모든 노드에 채굴을 시작시키는 트리거
	// GET /mine
	mux.HandleFunc("/mine", func(w http.ResponseWriter, r *http.Request) {
		var rec ContentRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "invalid content record", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		log.Printf("[API][MINE] Mining trigger received with content: %s", rec.ContentID)

		go triggerNetworkMining([]ContentRecord{rec}) // 데이터 전달

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "mining triggered",
			"content_id": rec.ContentID,
		})
	})
}
