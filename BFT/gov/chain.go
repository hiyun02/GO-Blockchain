package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// UpperChain (Gov 상위 체인)
// ----------------------------------------------------------------------------
// - 여러 Hos 체인으로부터 루트를 수집(pending)
// - 일정 시간이 지나면 자동으로 UpperBlock 생성 및 PoW 수행
// - 사용자의 명시적 요청 없이 주기적으로 블록을 채굴
////////////////////////////////////////////////////////////////////////////////

type UpperChain struct {
	govID         string
	pending       []AnchorRecord // 아직 블록에 포함되지 않은 Hos 루트 (HosID => Root)
	pendingMu     sync.Mutex
	lastBlockTime time.Time // 마지막 블록 생성 시각
}

// 합의 단계 상수 정의
const (
	ConsIdle       int32 = 0 // 대기 상태
	ConsPrePrepare int32 = 1 // 리더의 블록 제안 단계
	ConsPrepare    int32 = 2 // 노드 간 검증 및 투표 단계
	ConsCommit     int32 = 3 // 최종 합의 및 확정 단계
)

// 전역 상태 관리 변수
var (
	ch                 *UpperChain // 체인 접근을 위한 전역변수
	chainMu            sync.Mutex
	self               string                    // 현재 노드 주소 NODE_ADDR (예: "hos-node-01:5000")
	boot               string                    // 현재 네트워크 상의 부트노드 주소
	startedAt          = time.Now()              // 현재 노드 시작 시간
	isBoot             atomic.Bool               // 현재 노드가 부트노드인지 여부
	bootAddrMu         sync.RWMutex              // 부트노드 주소 접근 시 동시성 보호용 RW 잠금 객체
	hosBootMap         = make(map[string]string) // Gov 부트노드와 연결될 Hos 체인들의 부트노드 주소록
	hosBootMapMu       sync.RWMutex              // hosBootMap 접근 시 동시성 보호용 RW 잠금 객체
	ConsPhase          atomic.Int32              // 현재 BFT 합의 단계 (Idle, PrePrepare, Prepare, Commit)
	peers              []string
	peerMu             sync.Mutex
	peerAliveMap       = make(map[string]bool) // 노드 상태를 주소:생존여부 형태로 관리하는 맵
	aliveMu            sync.RWMutex
	peerPubKeys        = make(map[string]string) // 전체 노드의 공개키 관리객체
	pkMu               sync.RWMutex
	anchorMap          = make(map[string]AnchorInfo) // Hos 별 최신 Anchor 관리
	anchorMu           sync.RWMutex                  //
	ConsWatcherTime    = 1                           // 메모리풀 검사시간(1초)
	NetworkWatcherTime = 60                          // 노드 관리 기준시간(60초)
	ChainWatcherTime   = 300                         // 체인 관리 기준시간(300초)
)

// 체인 초기화
func newUpperChain(govID string) (*UpperChain, error) {
	ch = &UpperChain{
		govID:   govID,
		pending: []AnchorRecord{},
	}

	// 제네시스 블록 존재 여부 확인
	genesis, err := getBlockByIndex(0)
	// 제네시스 블록이 없는 경우
	if err != nil {
		log.Printf("[INIT] No genesis. Mining genesis...")
		genesis = createGenesisBlock(govID)

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
		putMeta("meta_gov_id", govID)
		log.Printf("[INIT] Success Appending local genesis. Waiting for sync...")
		return ch, nil
	}
	// block_0 존재하는 경우 => genesis.govID 를 meta_gov_id 로 저장
	if err := putMeta("meta_gov_id", genesis.GovID); err != nil {
		return nil, err
	}

	return ch, nil
}

// 수신된 블록 검증 및 반영
func onBlockReceived(ub UpperBlock) error {
	// 1. PBFT 정족수(2f+1) 및 서명 검증
	if err := verifyConsensusEvidence(ub); err != nil {
		return fmt.Errorf("consensus verification failed: %w", err)
	}

	// 2. 이전 블록 연결성 검증
	prev, err := getBlockByIndex(ub.Index - 1)
	if err != nil {
		return fmt.Errorf("load prev block: %w", err)
	}
	if ub.PrevHash != prev.BlockHash {
		return fmt.Errorf("invalid hash link")
	}

	// 3. 로컬 장부 반영
	if err := saveBlockToDB(ub); err != nil {
		return fmt.Errorf("save block: %w", err)
	}
	if err := updateIndicesForBlock(ub); err != nil {
		return fmt.Errorf("update indices: %w", err)
	}
	if err := setLatestHeight(ub.Index); err != nil {
		return fmt.Errorf("set height: %w", err)
	}

	ch.lastBlockTime = time.Now()

	// 4. 합의 상태 초기화
	ConsPhase.Store(ConsIdle)

	logInfo("[CHAIN] Accepted New BFT Block #%d (%s)", ub.Index, ub.BlockHash[:12])
	return nil
}

// 블록 내 2f+1개 이상의 유효한 서명이 있는지 확인
func verifyConsensusEvidence(ub UpperBlock) error {
	// 1. 정족수 계산
	peers := peersSnapshot()
	n := len(peers) + 1 // 피어들 + 나(Self)
	f := (n - 1) / 3
	required := 2*f + 1

	// 서명 개수 자체가 부족하면 즉시 리턴
	if len(ub.Signatures) < required {
		return fmt.Errorf("insufficient signatures: %d/%d", len(ub.Signatures), required)
	}

	// 2. 검증할 메시지 해시 생성 (블록 해시 기준)
	msgHash := sha256.Sum256([]byte(ub.BlockHash))

	validCount := 0
	checkedPeers := make(map[string]bool) // 동일 노드의 중복 서명 방지용

	// 3. 서명 슬라이스 순회 (여기서 addr은 인덱스 int입니다)
	for _, sigHex := range ub.Signatures {
		found := false

		// 내 서명인지 먼저 확인 (가장 빠름)
		myPubKey, _ := getMeta("meta_hos_pubkey")
		if !checkedPeers[self] && verifyECDSA(myPubKey, msgHash[:], sigHex) {
			validCount++
			checkedPeers[self] = true
			found = true
		}

		// 내 서명이 아니라면 피어들 명단에서 대조
		if !found {
			for _, pAddr := range peers {
				if checkedPeers[pAddr] {
					continue // 이미 검증 완료된 피어는 스킵
				}

				pubPem := peerPubKeys[pAddr]
				if pubPem == "" {
					continue
				}

				// ECDSA 대조 연산 (CPU 집약적)
				if verifyECDSA(pubPem, msgHash[:], sigHex) {
					validCount++
					checkedPeers[pAddr] = true
					found = true
					break // 이 서명의 주인을 찾았으므로 다음 서명으로
				}
			}
		}
	}

	// 4. 유효 정족수 최종 확인
	if validCount < required {
		return fmt.Errorf("valid signatures insufficient: %d/%d (required %d)", validCount, required, required)
	}

	log.Printf("[BFT] Block #%d verified with %d valid signatures", ub.Index, validCount)
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
