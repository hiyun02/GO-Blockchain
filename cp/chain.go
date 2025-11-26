package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// LowerChain (CP별 독립 하부체인, PoW 기반 분산 합의)
// ----------------------------------------------------------------------------
// - PoW 연산은 pow.go의 mineBlock() 호출
////////////////////////////////////////////////////////////////////////////////

type LowerChain struct {
	cpID          string
	difficulty    int             // 체인 난이도 (모든 노드 동일)
	pending       []ContentRecord // 아직 블록에 포함되지 않은 CP 루트 (CPID => Root)
	pendingMu     sync.Mutex
	lastBlockTime time.Time // 마지막 블록 생성 시각
}

// 전역 상태 관리 변수
var (
	ch                 *LowerChain  // 현재 체인 포인터
	self               string       // 현재 노드 주소 NODE_ADDR (예: "cp-node-01:5000")
	boot               string       // 현재 네트워크 상의 부트노드 주소
	startedAt          = time.Now() // 현재 노드 시작 시간
	isBoot             atomic.Bool  // 현재 노드가 부트노드인지 여부
	bootAddrMu         sync.RWMutex // 부트노드 주소 접근 시 동시성 보호용 RW 잠금 객체
	ottBoot            string       // ott 체인의 부트노드 주소 (예 : "ott-node-01:5000")
	ottBootMu          sync.RWMutex // ottBoot 접근 시 동시성 보호용 RW 잠금 객체
	GlobalDifficulty   = 4          // 전역 난이도 설정 (모든 노드 동일)
	isMining           atomic.Bool  // 내부적인 채굴 상태 플래그
	miningStop         atomic.Bool  // 다른 노드에게 영향받는 채굴 중단 플래그 (다른 노드가 성공하면 true)
	DiffStandardTime   = 20         // 난이도 조정 기준 시간(20초)
	MiningWatcherTime  = 30         // 채굴 기준시간(30초)
	NetworkWatcherTime = 60         // 노드 관리 기준시간(60초)
	ChainWatcherTime   = 300        // 체인 관리 기준시간(300초)
)

// 체인 초기화 및 제네시스 확인
func newLowerChain(cpID string) (*LowerChain, error) {
	ch = &LowerChain{
		cpID:       cpID,
		difficulty: GlobalDifficulty,
		pending:    []ContentRecord{},
	}

	// 제네시스 블록 존재 여부 확인
	genesis, err := getBlockByIndex(0)
	// 제네시스 블록이 없는 경우
	if err != nil {

		log.Printf("[INIT] No genesis. Mining genesis...")
		genesis = mineGenesisBlock(cpID)

		// 체인에 추가
		if err := saveBlockToDB(genesis); err != nil {
			return nil, fmt.Errorf("save genesis block: %w", err)
		}
		if err := updateIndicesForBlock(genesis); err != nil {
			return nil, fmt.Errorf("update genesis indices: %w", err)
		}
		if err := setLatestHeight(genesis.Index); err != nil {
			return nil, fmt.Errorf("set genesis height: %w", err)
		}
		ch.lastBlockTime = time.Now()

		// 부트노드는 여기서 meta_cp_id 저장
		putMeta("meta_cp_id", cpID)

		log.Printf("[INIT] Success Appending local genesis. Waiting for sync...")
		return ch, nil
	}
	// block_0 존재하는 경우 => genesis.cpID 를 meta_cp_id 로 저장
	if err := putMeta("meta_cp_id", genesis.CpID); err != nil {
		return nil, err
	}

	return ch, nil
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

// 외부 블록 수신 -> 검증 및 체인 반영
func onBlockReceived(lb LowerBlock) error {
	miningStop.Store(true) // 즉시 채굴 중단

	// 이전 블록 확인
	prev, err := getBlockByIndex(lb.Index - 1)
	if err != nil {
		return fmt.Errorf("load prev: %w", err)
	}

	// 검증
	if lb.PrevHash != prev.BlockHash {
		return fmt.Errorf("invalid prev hash")
	}
	if !validHash(lb.BlockHash, lb.Difficulty) {
		return fmt.Errorf("invalid PoW hash")
	}

	// 체인에 추가
	if err := saveBlockToDB(lb); err != nil {
		return fmt.Errorf("save block: %w", err)
	}
	if err := updateIndicesForBlock(lb); err != nil {
		return fmt.Errorf("update indices: %w", err)
	}
	if err := setLatestHeight(lb.Index); err != nil {
		return fmt.Errorf("set height: %w", err)
	}
	// 마지막 블록 생성 시각 업데이트
	ch.lastBlockTime = time.Now()
	// 부트노드일 경우, 서명하여 OTT 체인으로 제출
	if self == boot {
		submitAnchor(lb)
		logInfo("[BOOT] New Block's Anchor was sent By BootNode")
	}
	logInfo("[CHAIN] Accepted New Block #%d (%s)", lb.Index, lb.BlockHash[:12])
	return nil
}

// 체인의 메모리풀인 pending에 컨텐츠 내용 추가
func appendPending(entries []ContentRecord) {
	ch.pendingMu.Lock()
	ch.pending = append(ch.pending, entries...)
	ch.pendingMu.Unlock()
	log.Printf("[CHAIN][PENDING] Append pending entries (%d items)", len(entries))
}

// 체인의 메모리풀인 pending에 컨텐츠 내용 비우고 가져오기
func getPending() []ContentRecord {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	// 복사본 생성
	entries := make([]ContentRecord, len(ch.pending))
	copy(entries, ch.pending)
	// 원본 비우기
	ch.pending = []ContentRecord{}
	log.Printf("[CHAIN][PENDING] Pop pending entries (%d items)", len(entries))
	return entries
}

// 메모리풀이 비어있는 지 확인
func pendingIsEmpty() bool {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	return len(ch.pending) == 0
}

// 간단 로그 출력 함수
func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}
