package main

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// UpperChain (OTT 상위 체인)
// ----------------------------------------------------------------------------
// - 여러 CP 체인으로부터 루트를 수집(pending)
// - 일정 시간이 지나면 자동으로 UpperBlock 생성 및 PoW 수행
// - 사용자의 명시적 요청 없이 주기적으로 블록을 채굴
////////////////////////////////////////////////////////////////////////////////

type UpperChain struct {
	ottID         string
	difficulty    int
	pending       []AnchorRecord // 아직 블록에 포함되지 않은 CP 루트 (CPID => Root)
	pendingMu     sync.Mutex
	lastBlockTime time.Time // 마지막 블록 생성 시각
}

// 전역 상태 관리 변수
var (
	ch                 *UpperChain               // 체인 접근을 위한 전역변수
	self               string                    // 현재 노드 주소 NODE_ADDR (예: "cp-node-01:5000")
	boot               string                    // 현재 네트워크 상의 부트노드 주소
	startedAt          = time.Now()              // 현재 노드 시작 시간
	isBoot             atomic.Bool               // 현재 노드가 부트노드인지 여부
	bootAddrMu         sync.RWMutex              // 부트노드 주소 접근 시 동시성 보호용 RW 잠금 객체
	cpBootMap          = make(map[string]string) // OTT 부트노드와 연결될 CP 체인들의 부트노드 주소록
	cpBootMapMu        sync.RWMutex              // cpBootMap 접근 시 동시성 보호용 RW 잠금 객체
	GlobalDifficulty   = 4                       // 전역 난이도 설정 (모든 노드 동일)
	isMining           atomic.Bool               // 내부적인 채굴 상태 플래그
	miningStop         atomic.Bool               // 다른 노드에게 영향받는 채굴 중단 플래그 (다른 노드가 성공하면 true)
	DiffStandardTime   = 20                      // 난이도 조정 기준 시간(20초)
	MiningWatcherTime  = 30                      // 채굴 기준시간(30초)
	NetworkWatcherTime = 60                      // 노드 관리 기준시간(60초)
	ChainWatcherTime   = 300                     // 체인 관리 기준시간(300초)
)

// 체인 초기화
func newUpperChain(ottID string) (*UpperChain, error) {
	ch = &UpperChain{
		ottID:         ottID,
		difficulty:    GlobalDifficulty,
		pending:       []AnchorRecord{},
		lastBlockTime: time.Now(),
	}

	// 제네시스 블록 존재 여부 확인
	genesis, err := getBlockByIndex(0)
	// 제네시스 블록이 없는 경우
	if err != nil {
		// 제네시스 블록이 없고, 현재노드가 부트노드인 경우에만 제네시스블록 채굴
		if self == boot {
			log.Printf("[INIT] No genesis. Boot node mining genesis...")
			genesis = mineGenesisBlock(ottID)

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

			// 부트노드는 여기서 meta_ott_id 저장
			putMeta("meta_ott_id", ottID)
			return ch, nil
		}

		// 제네시스 없고 부트노드가 아니면, 아직 syncChain이 안 된 상태
		// => meta_ott_id는 지금 저장하면 안 됨
		log.Printf("[INIT] No local genesis. Waiting for sync...")
		return ch, nil
	}
	// block_0 존재하는 경우 => genesis.ottID 를 meta_ott_id 로 저장
	if err := putMeta("meta_cp_id", genesis.OttID); err != nil {
		return nil, err
	}

	return ch, nil
}

// 수신된 블록 검증 및 반영
func onBlockReceived(ub UpperBlock) error {
	miningStop.Store(true) // 다른 PoW 중단

	// 이전 블록 확인
	prev, err := getBlockByIndex(ub.Index - 1)
	if err != nil {
		return fmt.Errorf("load prev: %w", err)
	}

	// 검증
	if ub.PrevHash != prev.BlockHash {
		return fmt.Errorf("invalid prev hash")
	}
	if !validHash(ub.BlockHash, ub.Difficulty) {
		return fmt.Errorf("invalid PoW hash")
	}

	// 체인에 추가
	if err := saveBlockToDB(ub); err != nil {
		return fmt.Errorf("save block: %w", err)
	}
	if err := updateIndicesForBlock(ub); err != nil {
		return fmt.Errorf("update indices: %w", err)
	}
	if err := setLatestHeight(ub.Index); err != nil {
		return fmt.Errorf("set height: %w", err)
	}

	logInfo("[CHAIN][UPPER] Accepted UpperBlock #%d (%s)", ub.Index, ub.BlockHash[:12])
	return nil
}

// 체인의 메모리풀인 pending에 앵커 내용 추가
func appendPending(records []AnchorRecord) {
	ch.pendingMu.Lock()
	ch.pending = append(ch.pending, records...)
	ch.pendingMu.Unlock()
	log.Printf("[CHAIN][PENDING] Append pending entries (%d items)", len(records))
}

// 체인의 메모리풀인 pending에 앵커 내용 비우고 가져오기
func getPending() []AnchorRecord {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	// 복사본 생성
	entries := make([]AnchorRecord, len(ch.pending))
	copy(entries, ch.pending)
	// 원본 비우기
	ch.pending = []AnchorRecord{}
	log.Printf("[CHAIN][PENDING] Pop pending entries (%d items)", len(entries))
	return entries
}

// 메모리풀이 비어있는 지 확인
func pendingIsEmpty() bool {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	return len(ch.pending) == 0
}

func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}
