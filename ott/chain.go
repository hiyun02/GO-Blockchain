package main

import (
	"errors"
	"fmt"
	"sync"
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
	pendingAnchors map[string]string // 아직 블록에 포함되지 않은 CP 루트 (CPID => Root)
	pendingMu             sync.Mutex
	lastBlockTime  time.Time         // 마지막 블록 생성 시각
}

// 블록 생성 기준
var (
	ch            *UpperChain
	BlockInterval = 30 * time.Second // 30초마다 블록 생성 시도
)

// 체인 초기화
func newUpperChain(ottID string) (*UpperChain, error) {
	ch = &UpperChain{
		ottID:          ottID,
		difficulty:     GlobalDifficulty,
		pendingAnchors: make(map[string]string),
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
func (ch *UpperChain) appendAnchorToPending(cpID, root string) {
	if cpID == "" || root == "" {
		logInfo("invalid anchor data")
	}
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	ch.pendingAnchors[cpID] = root
	logInfo("[ANCHOR] Added CP anchor: %s -> %s", cpID, root[:8])
}

// 블록 생성 스레드 (주기적 자동 실행)
// ----------------------------------------------------------------------------
// - BlockInterval 주기로 실행
// - pendingAnchors가 존재하고, 마지막 블록 생성 이후 일정 시간이 지나면 finalizeBlock 호출
func (ch *UpperChain) startBlockWatcher() {
	ticker := time.NewTicker(BlockInterval)
	defer ticker.Stop()

	for range ticker.C {
		if len(ch.pendingAnchors) == 0 {
			continue // 아직 수집된 앵커 없음
		}
		if time.Since(ch.lastBlockTime) < BlockInterval {
			continue // 아직 주기 미도래
		}

		logInfo("[WATCHER][UPPER] Interval reached => Generating new block...")
		ch.lastBlockTime = time.Now()
	}
}

// 블록 생성 (pendingAnchors => 블록)
// ----------------------------------------------------------------------------
// - 조건: pendingAnchors가 존재하고, 시간 주기 도달 시
// - 실제 PoW 수행은 pow.go의 triggerNetworkMining()이 담당
func (ch *UpperChain) finalizeBlock() error {
	if len(ch.pendingAnchors) == 0 {
		return errors.New("no anchors to finalize")
	}

	// AnchorRecord로 변환 (PoW에 넘길 입력)
	anchors := make([]AnchorRecord, 0, len(ch.pendingAnchors))
	for cpID, root := range ch.pendingAnchors {
		anchors = append(anchors, AnchorRecord{
			CPID:      cpID,
			LowerRoot: root,
			// 추가 필드는 상황에 맞게 채워넣을 수 있음
			AnchorTimestamp: time.Now().Format(time.RFC3339),
		})
	}

	go triggerNetworkMining(anchors)
	// 대기 중인 앵커 초기화 (채굴이 시작되었으므로)
	ch.pendingAnchors = make(map[string]string)
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
