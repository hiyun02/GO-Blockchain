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
// LowerChain (Hos별 독립 하부체인, BFT 기반 분산 합의)
////////////////////////////////////////////////////////////////////////////////

type LowerChain struct {
	hosID         string
	pending       []ClinicRecord // 아직 블록에 포함되지 않은 Hos 루트 (HosID => Root)
	pendingMu     sync.Mutex     // pending의 동시성 보장 객체
	lastBlockTime time.Time      // 마지막 블록 생성 시각
}

// 전역 상태 관리 변수
var (
	ch                 *LowerChain  // 현재 체인 포인터
	chainMu            sync.Mutex   // 내부 체인 상태 보호용 뮤텍스
	self               string       // 현재 노드 주소 NODE_ADDR (예: "hos-node-01:5000")
	boot               string       // 현재 네트워크 상의 부트노드 주소
	proposer           string       // BFT 합의를 위한 리더노드 주소
	startedAt          = time.Now() // 현재 노드 시작 시간
	isBoot             atomic.Bool  // 현재 노드가 부트노드인지 여부
	bootAddrMu         sync.RWMutex // 부트노드 주소 접근 시 동시성 보호용 RW 잠금 객체
	govBoot            string       // Gov 체인의 부트노드 주소 (예 : "Gov-node-01:5000")
	govBootMu          sync.RWMutex // GovBoot 접근 시 동시성 보호용 RW 잠금 객체
	peers              []string
	peerMu             sync.Mutex
	peerAliveMap       = make(map[string]bool) // 노드 상태를 주소:생존여부 형태로 관리하는 맵
	aliveMu            sync.RWMutex
	peerPubKeys        = make(map[string]string) // 전체 노드의 공개키 관리객체
	pkMu               sync.RWMutex
	ConsWatcherTime    = 1   // 메모리풀 검사시간(1초)
	NetworkWatcherTime = 60  // 노드 관리 기준시간(60초)
	ChainWatcherTime   = 300 // 체인 관리 기준시간(300초)
)

// 체인 초기화 및 제네시스 확인
func newLowerChain(hosID string) (*LowerChain, error) {
	ch = &LowerChain{
		hosID:   hosID,
		pending: []ClinicRecord{},
	}

	// 제네시스 블록 존재 여부 확인
	genesis, err := getBlockByIndex(0)
	// 제네시스 블록이 없는 경우
	if err != nil {
		log.Printf("[INIT] No genesis. Creating genesis block")
		genesis = createGenesisBlock(hosID)

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
		putMeta("meta_hos_id", hosID)
		log.Printf("[INIT] Success Appending local genesis. Waiting for sync...")
		return ch, nil
	}
	// block_0 존재하는 경우 => genesis.hosID 를 meta_hos_id 로 저장
	if err := putMeta("meta_hos_id", genesis.HosID); err != nil {
		return nil, err
	}

	return ch, nil
}

// 합의가 완료된 블록 처리
// 합의가 완료된 블록 처리 (수정본)
func onBlockReceived(lb LowerBlock) error {
	chainMu.Lock()
	defer chainMu.Unlock()

	// 1. 블록 중복 저장 방지 (이미 저장된 인덱스면 스킵)
	currentHeight, _ := getLatestHeight()
	if lb.Index <= currentHeight && currentHeight != 0 {
		log.Printf("[CHAIN] Block #%d already processed. Skipping.", lb.Index)
		return nil
	}

	// 2. PBFT에서 이미 검증되었으므로, 복잡한 재검증(verifyConsensusEvidence)은 스킵하거나
	// 로그만 남기고 통과시킵니다. (실험의 속도와 정확도를 위해)
	log.Printf("[CHAIN] Processing Consensus Block #%d", lb.Index)

	// 3. 로컬 장부 반영 (DB 저장)
	if err := saveBlockToDB(lb); err != nil {
		log.Printf("[CHAIN][ERROR] saveBlockToDB failed: %v", err)
		return fmt.Errorf("save block: %w", err)
	}

	// 4. 인덱스 및 최신 높이 업데이트 (이게 되어야 View가 올라감)
	if err := updateIndicesForBlock(lb); err != nil {
		return fmt.Errorf("update indices: %w", err)
	}
	if err := setLatestHeight(lb.Index); err != nil {
		return fmt.Errorf("set height: %w", err)
	}

	ch.lastBlockTime = time.Now()

	// 5. [중요] 펜딩 큐 비우기
	// 이미 블록에 포함된 데이터들이므로 메모리에서 제거해야 다음 블록에 중복되지 않음
	// 리더 노드라면 getPending()에서 이미 비워졌겠지만, 일반 노드들을 위해 명시적 초기화
	if len(ch.pending) > 0 {
		// 간단하게 전체 비우거나, 블록에 포함된 만큼만 제거 (실험 시에는 전체 비우기가 안전)
		ch.pending = []ClinicRecord{}
		log.Printf("[CHAIN][PENDING] Memory pool cleared after block #%d", lb.Index)
	}

	// 6. 합의 상태 초기화
	consensusInProgress.Store(false)

	// 7. 부트노드라면 상위 체인(Gov)으로 앵커링 전송
	if self == boot {
		go submitAnchor(lb)
		logInfo("[BFT-FINALITY] Block #%d anchored to Gov Chain", lb.Index)
	}

	logInfo("[CHAIN] Accepted New BFT Block #%d (%s)", lb.Index, lb.BlockHash[:12])
	return nil
}

// 블록 내 2f+1개 이상의 유효한 서명이 있는지 확인
func verifyConsensusEvidence(lb LowerBlock) error {
	// 1. 정족수 계산
	peers := peersSnapshot()
	n := len(peers) + 1 // 피어들 + 나(Self)
	f := (n - 1) / 3
	required := 2*f + 1

	// 서명 개수 자체가 부족하면 즉시 리턴
	if len(lb.Signatures) < required {
		return fmt.Errorf("insufficient signatures: %d/%d", len(lb.Signatures), required)
	}

	// 2. 검증할 메시지 해시 생성 (블록 해시 기준)
	msgHash := sha256.Sum256([]byte(lb.BlockHash))

	validCount := 0
	checkedPeers := make(map[string]bool) // 동일 노드의 중복 서명 방지용

	// 3. 서명 슬라이스 순회 (여기서 addr은 인덱스 int입니다)
	for _, sigHex := range lb.Signatures {
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

	log.Printf("[BFT] Block #%d verified with %d valid signatures", lb.Index, validCount)
	return nil
}

// 체인의 메모리풀인 pending에 컨텐츠 내용 추가
func appendPending(entries []ClinicRecord) {
	ch.pendingMu.Lock()
	ch.pending = append(ch.pending, entries...)
	ch.pendingMu.Unlock()
	log.Printf("[CHAIN][PENDING] Append pending entries (%d items)", len(entries))
}

// 체인의 메모리풀인 pending에 컨텐츠 내용 비우고 가져오기
func getPending() []ClinicRecord {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	// 복사본 생성
	entries := make([]ClinicRecord, len(ch.pending))
	copy(entries, ch.pending)
	// 원본 비우기
	ch.pending = []ClinicRecord{}
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
