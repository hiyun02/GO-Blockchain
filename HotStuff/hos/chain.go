package main

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// LowerChain (Hos별 독립 하부체인, HotStuff 기반 분산 합의)
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
	proposer           string       // HotStuff 합의를 위한 현재 리더 주소
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
		log.Printf("[초기화] 제네시스 블록이 없어 새로 생성합니다.")
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
		log.Printf("[초기화] 로컬 제네시스 블록을 저장했습니다. 피어 동기화를 기다립니다.")
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

	// 블록 중복 저장 방지 (이미 저장된 인덱스면 스킵)
	currentHeight, _ := getLatestHeight()
	if lb.Index <= currentHeight && currentHeight != 0 {
		log.Printf("[체인] 블록 #%d은(는) 이미 처리되어 건너뜁니다.", lb.Index)
		return nil
	}
	if currentHeight >= 0 && lb.Index > 0 {
		prev, err := getBlockByIndex(currentHeight)
		if err != nil {
			return fmt.Errorf("이전 블록 조회 실패: %w", err)
		}
		if err := validateLowerBlock(lb, prev); err != nil {
			return fmt.Errorf("HotStuff 결정 블록 구조 검증 실패: %w", err)
		}
		if err := verifyConsensusEvidence(lb); err != nil {
			return fmt.Errorf("HotStuff 합의 증거 검증 실패: %w", err)
		}
	}
	// 로컬 장부 반영 (DB 저장)
	if err := saveBlockToDB(lb); err != nil {
		log.Printf("[체인][오류] 블록 DB 저장 실패: %v", err)
		return fmt.Errorf("save block: %w", err)
	}

	// 인덱스 및 최신 높이 업데이트
	if err := updateIndicesForBlock(lb); err != nil {
		return fmt.Errorf("update indices: %w", err)
	}
	if err := setLatestHeight(lb.Index); err != nil {
		return fmt.Errorf("set height: %w", err)
	}
	ch.lastBlockTime = time.Now()

	// 합의 상태 초기화
	finishHotStuffConsensus(lb)

	// 부트노드라면 상위 체인(Gov)으로 앵커링 전송
	if self == boot {
		go submitAnchor(lb)
		logInfo("[HotStuff][최종성] 블록 #%d의 Gov 체인 앵커링을 요청했습니다.", lb.Index)
	}

	logInfo("[체인] HotStuff 확정 블록 #%d을(를) 반영했습니다. (해시=%s)", lb.Index, shortHash(lb.BlockHash))
	return nil
}

// 블록에 Prepare → Pre-Commit → Commit QC가 완전하게 포함되어 있는지 확인한다.
func verifyConsensusEvidence(lb LowerBlock) error {
	if lb.HotStuff == nil {
		return fmt.Errorf("HotStuff 합의 증거가 없습니다")
	}
	proof := lb.HotStuff
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
		if check.qc.BlockHash != lb.BlockHash {
			return fmt.Errorf("%s QC 블록 해시 불일치", check.name)
		}
		if err := verifyQuorumCertificate(check.qc); err != nil {
			return fmt.Errorf("%s QC 검증 실패: %w", check.name, err)
		}
	}
	if !(proof.PrepareQC.View == proof.PreCommitQC.View && proof.PreCommitQC.View == proof.CommitQC.View) {
		return fmt.Errorf("QC 뷰 번호가 서로 다릅니다")
	}
	log.Printf("[HotStuff][검증] 블록 #%d의 3단계 QC가 모두 유효합니다. (뷰=%d, Commit 서명=%d)",
		lb.Index, proof.CommitQC.View, len(proof.CommitQC.Signatures))
	return nil
}

// 체인의 메모리풀인 pending에 컨텐츠 내용 추가
func appendPending(entries []ClinicRecord) {
	ch.pendingMu.Lock()
	ch.pending = append(ch.pending, entries...)
	ch.pendingMu.Unlock()
	log.Printf("[체인][대기열] 합의 대기 레코드 %d건을 추가했습니다.", len(entries))
}

// 체인의 메모리풀인 pending에 컨텐츠 내용 비우고 가져오기
func popPending() []ClinicRecord {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	// 복사본 생성
	entries := make([]ClinicRecord, len(ch.pending))
	copy(entries, ch.pending)
	// 원본 비우기
	ch.pending = []ClinicRecord{}
	log.Printf("[체인][대기열] 합의 대상 레코드 %d건을 꺼냈습니다.", len(entries))
	return entries
}

// 메모리풀의 엔트리 개수 확인
func getPendingCnt() int {
	ch.pendingMu.Lock()
	defer ch.pendingMu.Unlock()
	return len(ch.pending)
}

// 간단 로그 출력 함수
func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}
