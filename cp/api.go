// api.go
package cp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

// JSON 헬퍼
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// RegisterAPI : main.go에서 mux와 LowerChain을 넘겨 핸들만 등록
func RegisterAPI(mux *http.ServeMux, chain *LowerChain) {
	// 1) 콘텐츠 추가 (pending 적재 + 저널 기록은 blockchain.go 내부 AddContent에서 처리)
	// POST /content/add
	mux.HandleFunc("/content/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var rec ContentRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		// 최소 필수값 검증 (머클/증명 안정성)
		if rec.ContentID == "" || rec.Fingerprint == "" || rec.StorageAddr == "" {
			http.Error(w, "missing required fields (content_id, fingerprint, storage_addr)", http.StatusBadRequest)
			return
		}
		chain.addContent(rec)
		// pending 상태 가시성
		cnt, bytes := chain.pendingStats()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"queued": map[string]int{"count": cnt, "bytes": bytes},
		})
	})

	// 2) 블록 확정 (임계치 충족 시에만; force=true로 우회 가능)
	// POST /block/finalize?force=true|false
	mux.HandleFunc("/block/finalize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		force := r.URL.Query().Get("force") == "true"
		blk, err := chain.finalizeIfEligible(force)
		if err != nil {
			if err == ErrNotEligible {
				cnt, bytes := chain.pendingStats()
				writeJSON(w, http.StatusPreconditionFailed, map[string]any{ // 412
					"ok":         false,
					"reason":     "threshold_not_met",
					"pending":    map[string]int{"count": cnt, "bytes": bytes},
					"thresholds": map[string]int{"min_count": MaxPendingEntries, "min_bytes": MaxPendingBytes},
					"hint":       "add more contents or call with force=true",
				})
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "block": blk})
	})

	// 3) 최신 머클루트 (OTT 앵커용)
	// GET /block/root
	mux.HandleFunc("/block/root", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		root := chain.LatestRoot() // storage의 getLatestRoot 사용
		writeJSON(w, http.StatusOK, map[string]string{"root": root})
	})

	// 4) 블록 조회: 인덱스
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

	// 5) 블록 조회: 해시
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

	// 6) 키워드로 블록 검색(정확 일치: cid/fp/info_title)
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

	// 7) 전체 장부 조회 (페이지네이션)
	// GET /blocks?offset=<int>&limit=<int>
	// storage.go에 listBlocksPaginated 추가한 버전 기준
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

	// 8) 머클 증명 제공 (색인 기반 즉시 접근)
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
}

// 현재 노드가 알고 있는 피어 리스트 반환
// GET /peers
func getPeers(w http.ResponseWriter, r *http.Request) {
	peerMu.Lock()
	defer peerMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

// 새로운 피어 등록
// POST /addPeer (Body: "ip:port")
func addPeer(w http.ResponseWriter, r *http.Request) {
	var peer string
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, "invalid peer format", http.StatusBadRequest)
		return
	}

	peerMu.Lock()
	peers = append(peers, peer)
	peerMu.Unlock()

	log.Printf("[API] New peer added: %s\n", peer)
	w.Write([]byte("Peer added"))
}
