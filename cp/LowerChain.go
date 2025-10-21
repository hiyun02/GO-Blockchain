package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// LowerChain (CP별 독립 하부체인, 확정형)
// ----------------------------------------------------------------------------
// 1) 각 CP는 자신의 하부체인(LowerChain)을 별도로 운용함 ( CP : Chain = 1 : 1 )
// 2) 합의는 확정형이므로 PoW/Nonce 없음, 포크 전제하지 않음
// 3) 블록 헤더의 해시는 헤더 서브셋만 캐노니컬 JSON 직렬화 => SHA-256(hex)
//    - 포함: Index, CpID, PrevHash, Timestamp, MerkleRoot
//    - 제외: Entries, BlockHash (자가참조 및 가변 대용량 데이터 배제)
// 4) MerkleRoot/Proof는 공통 유틸(crypto_merkle.go)의 규칙 고수
//    - 잎이 홀수면 마지막 잎 "복제" 규칙을 루트/증명 모두 동일 적용
// 5) 콘텐츠 해시는 "불변 서브셋"만(예: ContentID, Fingerprint, StorageAddr) 사용
//    - Info/DRM/Timestamp 등 가변 메타는 머클 해시에 포함하지 않음
////////////////////////////////////////////////////////////////////////////////

// LowerChain : CP 별 독립 체인 (확정형)
// - cpID : 체인 정체성 (모든 노드 동일)
// - pending : 아직 블록에 확정하지 않은 콘텐츠들
// - blocks  : 메모리 상의 블록 리스트 (스토리지가 있으면 생략 가능)
type LowerChain struct {
	cpID    string
	mu      sync.Mutex
	pending []ContentRecord
}

// 블록 finalize 기준
var (
	MaxPendingEntries = 500
	MaxPendingBytes   = 4 * 1024 * 1024 // 4MB
)

// cpID를 주입받아 제네시스 및 체인 생성
func newLowerChain(cpID string) (*LowerChain, error) {
	ch := &LowerChain{cpID: cpID, pending: make([]ContentRecord, 0)}

	// 제네시스 존재?
	blk0, err := getBlockByIndex(0)
	if err != nil {
		// 없으면 생성
		genesis := createGenesisBlock(cpID)
		if err := saveBlockToDB(genesis); err != nil {
			return nil, fmt.Errorf("save genesis: %w", err)
		}
		if err := updateIndicesForBlock(genesis); err != nil {
			return nil, fmt.Errorf("index genesis: %w", err)
		}
		if err := putMeta("meta_cp_id", cpID); err != nil {
			return nil, fmt.Errorf("meta cp_id: %w", err)
		}
		if err := setLatestHeight(0); err != nil {
			return nil, fmt.Errorf("meta height: %w", err)
		}
		return ch, nil
	}

	// 제네시스 있으면 cp_id 일치성 확인
	if blk0.CpID != cpID {
		return nil, fmt.Errorf("cp_id mismatch: db=%q new=%q", blk0.CpID, cpID)
	}
	if v, ok := getMeta("meta_cp_id"); ok && v != cpID {
		return nil, fmt.Errorf("cp_id mismatch(meta): db=%q new=%q", v, cpID)
	}

	// 최신 높이 메타 없으면 복구
	if _, ok := getLatestHeight(); !ok {
		h := 0
		for {
			if _, err := getBlockByIndex(h); err != nil {
				break
			}
			h++
		}
		if h == 0 {
			_ = setLatestHeight(0)
		} else {
			_ = setLatestHeight(h - 1)
		}
	}
	return ch, nil
}

// 신규 콘텐츠를 pending 큐에 적재
func (ch *LowerChain) addContent(rec ContentRecord) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.pending = append(ch.pending, rec)
}

// pending을 하나의 블록으로 확정
func (ch *LowerChain) finalizeBlock() (LowerBlock, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if len(ch.pending) == 0 {
		return LowerBlock{}, errors.New("no pending contents to finalize")
	}

	// 잎 해시 (불변 서브셋)
	leaf := make([]string, len(ch.pending))
	for i, r := range ch.pending {
		leaf[i] = hashContentRecord(r)
	}

	root := merkleRootHex(leaf)

	// prev 로드
	prevH, ok := getLatestHeight()
	if !ok {
		return LowerBlock{}, errors.New("height_latest missing")
	}
	prev, err := getBlockByIndex(prevH)
	if err != nil {
		return LowerBlock{}, fmt.Errorf("load prev: %w", err)
	}

	nb := LowerBlock{
		Index:      prev.Index + 1,
		CpID:       ch.cpID,
		PrevHash:   prev.BlockHash,
		Timestamp:  time.Now().Format(time.RFC3339),
		Entries:    append([]ContentRecord(nil), ch.pending...),
		MerkleRoot: root,
	}
	nb.BlockHash = nb.computeHash()

	// 저장 & 인덱스 & 메타 갱신
	if err := saveBlockToDB(nb); err != nil {
		return LowerBlock{}, fmt.Errorf("save block: %w", err)
	}
	if err := updateIndicesForBlock(nb); err != nil {
		return LowerBlock{}, fmt.Errorf("update indices: %w", err)
	}
	if err := setLatestHeight(nb.Index); err != nil {
		return LowerBlock{}, fmt.Errorf("set height: %w", err)
	}

	// pending 비움
	ch.pending = ch.pending[:0]
	return nb, nil
}

// 최신 루트 (storage 캐시 사용)
func (ch *LowerChain) LatestRoot() string {
	return getLatestRoot()
}

// content_id로 머클 증명 생성
// 반환: (레코드, 포함된 블록, 증명경로, 존재여부)
func (ch *LowerChain) getContentWithProofIndexed(contentID string) (ContentRecord, LowerBlock, [][2]string, bool) {
	// storage의 "cid_" 색인을 직접 읽어와 접근
	ptrKey := "cid_" + contentID
	ptrBytes, err := db.Get([]byte(ptrKey), nil)
	if err != nil {
		return ContentRecord{}, LowerBlock{}, nil, false
	}

	parts := strings.Split(string(ptrBytes), ":")
	if len(parts) != 2 {
		return ContentRecord{}, LowerBlock{}, nil, false
	}
	bi, err1 := strconv.Atoi(parts[0])
	ei, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return ContentRecord{}, LowerBlock{}, nil, false
	}

	blk, err := getBlockByIndex(bi)
	if err != nil || ei < 0 || ei >= len(blk.Entries) {
		return ContentRecord{}, LowerBlock{}, nil, false
	}
	rec := blk.Entries[ei]

	leaf := make([]string, len(blk.Entries))
	for i, r := range blk.Entries {
		leaf[i] = hashContentRecord(r)
	}
	proof := merkleProof(leaf, ei)

	return rec, blk, proof, true
}

// 대략 크기 추정 (배치 판단용, 정밀할 필요 X)
func approxSize(list []ContentRecord) int {
	total := 0
	for _, r := range list {
		b, _ := json.Marshal(r)
		total += len(b)
	}
	return total
}

// 가시성 제공용: 현재 pending 상태
func (ch *LowerChain) pendingStats() (count int, bytes int) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return len(ch.pending), approxSize(ch.pending)
}

// 임계치 충족 여부 판단
func (ch *LowerChain) eligibleToFinalize() (ok bool, reason string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if len(ch.pending) == 0 {
		return false, "no pending contents"
	}
	size := approxSize(ch.pending)
	needEntries := len(ch.pending) >= MaxPendingEntries
	needBytes := size >= MaxPendingBytes
	if needEntries || needBytes {
		return true, ""
	}
	return false, fmt.Sprintf("threshold not met (count=%d/%d, bytes=%d/%d)",
		len(ch.pending), MaxPendingEntries, size, MaxPendingBytes)
}

// 조건부 커밋: 임계치 미달시 에러 반환, force면 무시하고 커밋
var ErrNotEligible = errors.New("not eligible to finalize")

// 조건부 커밋( force=false면 임계치 미달 시 ErrNotEligible 반환
func (ch *LowerChain) finalizeIfEligible(force bool) (LowerBlock, error) {
	if !force {
		if ok, _ := ch.eligibleToFinalize(); !ok {
			return LowerBlock{}, ErrNotEligible
		}
	}
	return ch.finalizeBlock() // 여기엔 네가 이미 구현한 확정 로직 사용
}
