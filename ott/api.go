// ott/api.go
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

var (
	keyAPIEnabled = strings.ToLower(os.Getenv("OTT_KEY_API_ENABLED")) == "true"
	keyAPIToken   = os.Getenv("OTT_KEY_API_TOKEN")
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func RegisterUpperAPI(mux *http.ServeMux) {
	// (DEV 전용) HMAC 키 등록
	mux.HandleFunc("/upper/anchor/key", func(w http.ResponseWriter, r *http.Request) {
		if !keyAPIEnabled {
			http.Error(w, "key api disabled", http.StatusForbidden)
			return
		}
		if keyAPIToken != "" && r.Header.Get("X-Admin-Token") != keyAPIToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			CPID   string `json:"cp_id"`
			Secret string `json:"secret"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.CPID == "" || in.Secret == "" {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := setHMACKey(in.CPID, in.Secret); err != nil {
			http.Error(w, "save key error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// 계약 등록/갱신
	mux.HandleFunc("/upper/contract/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var c ContractData
		if json.NewDecoder(r.Body).Decode(&c) != nil || c.CPID == "" || c.ExpiryTimestamp == "" {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := setContract(c.CPID, c); err != nil {
			http.Error(w, "save contract error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// 앵커 수신(서명+ts 검증)
	mux.HandleFunc("/upper/anchor/receive", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			CPID      string `json:"cp_id"`
			LowerRoot string `json:"lower_root"`
			Timestamp string `json:"ts"`
			Signature string `json:"sig"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil ||
			in.CPID == "" || in.LowerRoot == "" || in.Timestamp == "" || in.Signature == "" {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := verifyAndStoreAnchor(in.CPID, in.LowerRoot, in.Timestamp, in.Signature); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// UpperBlock 확정 (요청에 cp_ids 지정)
	// POST /upper/block/finalize { "cp_ids": ["CP-A","CP-B"] }
	mux.HandleFunc("/upper/block/finalize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			CPIDs []string `json:"cp_ids"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.CPIDs) == 0 {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}

		// 마지막 블록 or 제네시스
		var last UpperBlock
		if h, ok := getHeightLatest(); ok {
			b, err := getBlockByIndex(h)
			if err != nil {
				http.Error(w, "load last block error", http.StatusInternalServerError)
				return
			}
			last = b
		} else {
			gen := createGenesisBlock()
			if err := saveBlock(gen); err != nil {
				http.Error(w, "save genesis error", http.StatusInternalServerError)
				return
			}
			_ = setHeightLatest(0)
			last = gen
		}

		// 대상 CP들의 계약+앵커로 UpperRecord 구성
		records := make([]UpperRecord, 0, len(in.CPIDs))
		for _, cp := range in.CPIDs {
			contract, okC := getContract(cp)
			anchor, okA := getAnchor(cp)
			if !(okC && okA) {
				continue
			}
			rec := UpperRecord{
				CPID:             cp,
				ContractSnapshot: contract,
				LowerRoot:        anchor.LowerRoot,
				AccessCatalog:    contract.AllowedContentIDs,
				AnchorTimestamp:  anchor.Timestamp,
			}
			records = append(records, rec)
		}

		nb := newUpperBlock(last, records)
		if err := saveBlock(nb); err != nil {
			http.Error(w, "save block error", http.StatusInternalServerError)
			return
		}
		_ = setHeightLatest(nb.Index)

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"count":  len(records),
			"block":  nb,
			"height": nb.Index,
		})
	})

	// 블록 조회
	mux.HandleFunc("/upper/block/index", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		n := atoiSafe(id)
		blk, err := getBlockByIndex(n)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, blk)
	})

	// (선택) 최신 앵커/계약 조회(간단)
	mux.HandleFunc("/upper/anchor/get", func(w http.ResponseWriter, r *http.Request) {
		cp := r.URL.Query().Get("cp_id")
		if cp == "" {
			http.Error(w, "cp_id required", http.StatusBadRequest)
			return
		}
		a, ok := getAnchor(cp)
		if !ok {
			http.Error(w, "no anchor", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, a)
	})
	mux.HandleFunc("/upper/contract/get", func(w http.ResponseWriter, r *http.Request) {
		cp := r.URL.Query().Get("cp_id")
		if cp == "" {
			http.Error(w, "cp_id required", http.StatusBadRequest)
			return
		}
		c, ok := getContract(cp)
		if !ok {
			http.Error(w, "no contract", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, c)
	})
}

func atoiSafe(s string) int {
	n := 0
	for i := range s {
		c := s[i]
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
