package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// UpperChain (OTT 상위 체인)
// ----------------------------------------------------------------------------
// - 여러 CP 체인으로부터 루트를 수집(pendingAnchors)
// - 일정 시간이 지나면 자동으로 UpperBlock 생성 및 PoW 수행
// - 사용자의 명시적 요청 없이 주기적으로 블록을 채굴
////////////////////////////////////////////////////////////////////////////////

type UpperChain struct {
	ottID          string
	difficulty     int
	pendingAnchors map[string]AnchorRecord // 아직 블록에 포함되지 않은 CP 루트 (CPID => Root)
	pendingMu      sync.Mutex
	lastBlockTime  time.Time // 마지막 블록 생성 시각
}

// 전역 상태 관리 변수
var (
	self          string                    // 현재 노드 주소 NODE_ADDR (예: "cp-node-01:5000")
	boot          string                    // 현재 네트워크 상의 부트노드 주소
	startedAt     = time.Now()              // 현재 노드 시작 시간
	isBoot        atomic.Bool               // 현재 노드가 부트노드인지 여부
	bootAddrMu    sync.RWMutex              // 부트노드 주소 접근 시 동시성 보호용 RW 잠금 객체
	ch            *UpperChain               // 체인 접근을 위한 전역변수
	BlockInterval = 30 * time.Second        // 블록 채굴 기준 (30초마다 블록 생성 시도)
	cpBootMap     = make(map[string]string) // OTT 부트노드와 연결될 CP 체인들의 부트노드 주소록
	cpBootMapMu   sync.RWMutex              // cpBootMap 접근 시 동시성 보호용 RW 잠금 객체

)

// 체인 초기화
func newUpperChain(ottID string) (*UpperChain, error) {
	ch = &UpperChain{
		ottID:          ottID,
		difficulty:     GlobalDifficulty,
		pendingAnchors: make(map[string]AnchorRecord),
		lastBlockTime:  time.Now(),
	}

	// 제네시스 블록 존재 여부 확인
	blk0, err := getBlockByIndex(0)
	if err != nil {
		genesis := createGenesisBlock(ottID)
		if err := saveBlockToDB(genesis); err != nil {
			return nil, fmt.Errorf("save genesis: %w", err)
		}
		if err := updateIndicesForBlock(genesis); err != nil {
			return nil, fmt.Errorf("index genesis: %w", err)
		}
		if err := setLatestHeight(0); err != nil {
			return nil, fmt.Errorf("meta height: %w", err)
		}
		logInfo("[INIT][CHAIN] Created genesis block for %s", ottID)
	} else {
		logInfo("[INIT][CHAIN] Loaded existing OTT chain (genesis=%s)", blk0.BlockHash[:12])
	}

	// 블록 생성 스레드 시작
	go ch.startBlockWatcher()

	return ch, nil
}

// CP 앵커 수신 (서명된 루트)
// ----------------------------------------------------------------------------
// - CP 체인에서 서명된 MerkleRoot 제출 시 호출
// - 블록에 바로 포함되지 않고 pendingAnchors에 임시 저장
func (ch *UpperChain) appendAnchorToPending(ar AnchorRecord) {
	if ar.CPID == "" || ar.LowerRoot == "" {
		logInfo("invalid anchor data")
		return
	}
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()

	ch.pendingAnchors[ar.CPID] = ar
	logInfo("[ANCHOR] Added CP anchor object: %s -> %s", ar.CPID, ar.LowerRoot[:8])
}

// 블록 생성 스레드 (주기적 자동 실행)
// ----------------------------------------------------------------------------
// - BlockInterval 주기로 실행
// - pendingAnchors가 존재하고, 마지막 블록 생성 이후 일정 시간이 지나면 finalizeBlock 호출
func (ch *UpperChain) startBlockWatcher() {
	logInfo("[WATCHER][BLOCK] BLOCK MINE WATCHER BEGIN")
	ticker := time.NewTicker(BlockInterval)
	defer ticker.Stop()

	for range ticker.C {
		if len(ch.pendingAnchors) == 0 {
			continue // 아직 수집된 앵커 없음
		}
		if time.Since(ch.lastBlockTime) < BlockInterval {
			continue // 아직 주기 미도래
		}

		logInfo("[WATCHER][BLOCK] Interval reached => Finalizing new block...")

		// 3) UpperBlock 생성 트리거
		if err := ch.finalizeBlock(); err != nil {
			logInfo("[WATCHER][CHAIN] BLOCK finalize error: %v", err)
		}
	}
}

// 블록 생성 (pendingAnchors => 블록)
// ----------------------------------------------------------------------------
// - 조건: pendingAnchors가 존재하고, 시간 주기 도달 시
// - 실제 PoW 수행은 pow.go의 triggerNetworkMining()이 담당
func (ch *UpperChain) finalizeBlock() error {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()

	if len(ch.pendingAnchors) == 0 {
		return errors.New("no anchors to finalize")
	}

	// AnchorRecord 리스트 그대로 출력
	anchors := make([]AnchorRecord, 0, len(ch.pendingAnchors))
	for _, ar := range ch.pendingAnchors {
		anchors = append(anchors, ar) // 이미 AnchorRecord 이므로 그대로 사용
	}

	// PoW 블록 생성 요청 (UpperChain용 mining)
	go triggerNetworkMining(anchors)

	// 펜딩 초기화
	ch.pendingAnchors = make(map[string]AnchorRecord)

	return nil
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

func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}
