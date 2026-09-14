package main

import (
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
// - 일정 시간이 지나면 HotStuff 합의로 UpperBlock 확정
// - 확정 블록에는 Prepare/Pre-Commit/Commit QC를 영구 저장
////////////////////////////////////////////////////////////////////////////////

type UpperChain struct {
	govID         string
	pending       []AnchorRecord // 아직 블록에 포함되지 않은 Hos 루트 (HosID => Root)
	pendingMu     sync.Mutex
	lastBlockTime time.Time // 마지막 블록 생성 시각
}

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
		log.Printf("[초기화] Gov 제네시스 블록이 없어 생성합니다.")
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
		log.Printf("[초기화] Gov 제네시스 블록을 저장했습니다. 피어 동기화를 기다립니다.")
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
	chainMu.Lock()
	defer chainMu.Unlock()

	currentHeight, _ := getLatestHeight()
	if ub.Index <= currentHeight {
		log.Printf("[체인] Gov 블록 #%d은(는) 이미 처리되어 건너뜁니다.", ub.Index)
		return nil
	}
	previous, err := getBlockByIndex(currentHeight)
	if err != nil {
		return fmt.Errorf("이전 Gov 블록 조회 실패: %w", err)
	}
	if err := validateUpperBlock(ub, previous); err != nil {
		return fmt.Errorf("HotStuff 결정 Gov 블록 구조 검증 실패: %w", err)
	}
	if err := verifyConsensusEvidence(ub); err != nil {
		return fmt.Errorf("HotStuff Gov 합의 증거 검증 실패: %w", err)
	}

	if err := saveBlockToDB(ub); err != nil {
		return fmt.Errorf("Gov 블록 저장 실패: %w", err)
	}
	if err := updateIndicesForBlock(ub); err != nil {
		return fmt.Errorf("update indices: %w", err)
	}
	if err := setLatestHeight(ub.Index); err != nil {
		return fmt.Errorf("set height: %w", err)
	}

	ch.lastBlockTime = time.Now()

	finishHotStuffConsensus(ub)
	logInfo("[체인] HotStuff 확정 Gov 블록 #%d을(를) 반영했습니다. (해시=%s)", ub.Index, shortHash(ub.BlockHash))
	return nil
}

// 블록에 Prepare → Pre-Commit → Commit QC가 완전하게 포함되어 있는지 확인한다.
func verifyConsensusEvidence(ub UpperBlock) error {
	if ub.HotStuff == nil {
		return fmt.Errorf("HotStuff 합의 증거가 없습니다")
	}
	proof := ub.HotStuff
	checks := []struct {
		name  string
		phase HotStuffPhase
		qc    QuorumCertificate
	}{
		{"Prepare", PhasePrepare, proof.PrepareQC},
		{"Pre-Commit", PhasePreCommit, proof.PreCommitQC},
		{"Commit", PhaseCommit, proof.CommitQC},
	}
	for _, check := range checks {
		if check.qc.Phase != check.phase {
			return fmt.Errorf("%s QC 단계가 올바르지 않습니다: %s", check.name, check.qc.Phase)
		}
		if check.qc.BlockHash != ub.BlockHash {
			return fmt.Errorf("%s QC Gov 블록 해시 불일치", check.name)
		}
		if err := verifyQuorumCertificate(check.qc); err != nil {
			return fmt.Errorf("%s QC 검증 실패: %w", check.name, err)
		}
	}
	if proof.PrepareQC.View != proof.PreCommitQC.View || proof.PreCommitQC.View != proof.CommitQC.View {
		return fmt.Errorf("Gov QC 뷰 번호가 서로 다릅니다")
	}
	log.Printf("[HotStuff][Gov 검증] 블록 #%d의 3단계 QC가 모두 유효합니다. (뷰=%d, Commit 서명=%d)",
		ub.Index, proof.CommitQC.View, len(proof.CommitQC.Signatures))
	return nil
}

// 체인의 메모리풀인 pending에 앵커 내용 추가
func appendPending(records []AnchorRecord) {
	ch.pendingMu.Lock()
	ch.pending = append(ch.pending, records...)
	ch.pendingMu.Unlock()
	log.Printf("[체인][Gov 대기열] 검증된 앵커 %d건을 추가했습니다.", len(records))
}

// 체인의 메모리풀인 pending에 앵커 내용 비우고 가져오기
func popPending() []AnchorRecord {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	// 복사본 생성
	entries := make([]AnchorRecord, len(ch.pending))
	copy(entries, ch.pending)
	// 원본 비우기
	ch.pending = []AnchorRecord{}
	log.Printf("[체인][Gov 대기열] 합의 대상 앵커 %d건을 꺼냈습니다.", len(entries))
	return entries
}

// 메모리풀이 비어있는 지 확인
func getPendingCnt() int {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	return len(ch.pending)
}

func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}
