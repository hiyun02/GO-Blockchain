package main

import (
	"encoding/hex"
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
	return acceptBlock(lb, false)
}

// onVerifiedBlockReceived는 현재 뷰에서 Commit 서명을 이미 검증한 결정 블록을 반영한다.
// P2P 동기화처럼 외부에서 받은 블록은 기본 경로에서 합의 증거를 다시 검증한다.
func onVerifiedBlockReceived(lb LowerBlock) error {
	return acceptBlock(lb, true)
}

func acceptBlock(lb LowerBlock, consensusEvidenceVerified bool) error {
	chainMu.Lock()
	defer chainMu.Unlock()

	// 블록 중복 저장 방지 (이미 저장된 인덱스면 스킵)
	currentHeight, _ := getLatestHeight()
	if lb.Index <= currentHeight && currentHeight != 0 {
		log.Printf("[CHAIN] Block #%d already processed. Skipping.", lb.Index)
		return nil
	}
	if lb.Index > 0 {
		previous, err := getBlockByIndex(currentHeight)
		if err != nil {
			return fmt.Errorf("이전 블록 조회 실패: %w", err)
		}
		if err := validateLowerBlockStructure(lb, previous); err != nil {
			return fmt.Errorf("PBFT 결정 블록 구조 검증 실패: %w", err)
		}
		if !consensusEvidenceVerified {
			if err := verifyConsensusEvidence(lb); err != nil {
				return fmt.Errorf("PBFT 합의 증거 검증 실패: %w", err)
			}
		}
	}
	// 로컬 장부 반영 (DB 저장)
	if err := saveBlockToDB(lb); err != nil {
		log.Printf("[CHAIN][ERROR] saveBlockToDB failed: %v", err)
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
	consensusInProgress.Store(false)

	// 부트노드라면 상위 체인(Gov)으로 앵커링 전송
	if self == boot {
		go submitAnchor(lb)
		logInfo("[BFT-FINALITY] Block #%d anchored to Gov Chain", lb.Index)
	}

	logInfo("[CHAIN] Accepted New BFT Block #%d (%s)", lb.Index, lb.BlockHash[:12])
	return nil
}

// 블록에 당시 참여자 중 n-f개 이상의 유효한 Commit 서명이 있는지 확인
func verifyConsensusEvidence(lb LowerBlock) error {
	if lb.ConsensusVersion < PBFTConsensusVersion {
		return verifyLegacyConsensusEvidence(lb)
	}
	if lb.ConsensusVersion != PBFTConsensusVersion {
		return fmt.Errorf("지원하지 않는 PBFT 합의 버전입니다: %d", lb.ConsensusVersion)
	}
	if lb.PBFT == nil {
		return fmt.Errorf("PBFT 합의 증거가 없습니다")
	}
	proof := lb.PBFT
	if proof.View != lb.Index || proof.Leader != lb.Proposer || !isSortedUnique(proof.Participants) ||
		!containsParticipant(proof.Participants, proof.Leader) {
		return fmt.Errorf("PBFT 뷰, 리더 또는 참여자 스냅샷이 올바르지 않습니다")
	}
	required := quorumSizeFor(len(proof.Participants))
	if len(proof.CommitVotes) < required {
		return fmt.Errorf("PBFT Commit 서명 부족: %d/%d", len(proof.CommitVotes), required)
	}
	digest := pbftVoteDigest(lb.HosID, proof.View, PhaseCommit, lb.BlockHash, proof.Leader, proof.Participants)
	seen := make(map[string]bool, len(proof.CommitVotes))
	for _, vote := range proof.CommitVotes {
		if seen[vote.Voter] || !containsParticipant(proof.Participants, vote.Voter) {
			return fmt.Errorf("중복되었거나 참여자가 아닌 PBFT Commit 서명자: %s", vote.Voter)
		}
		seen[vote.Voter] = true
		publicKey, ok := pbftPublicKeyFor(vote.Voter)
		if !ok || !verifyECDSA(publicKey, digest, vote.Signature) {
			return fmt.Errorf("서명자 %s의 PBFT Commit 서명이 유효하지 않습니다", vote.Voter)
		}
	}
	log.Printf("[PBFT][검증] 블록 #%d의 Commit 서명 %d개를 확인했습니다. (정족수=%d)", lb.Index, len(proof.CommitVotes), required)
	return nil
}

// verifyLegacyConsensusEvidence는 업그레이드 전에 생성된 블록의 기존 서명 형식을 검증한다.
// 새 합의 제안에는 사용할 수 없으며, 버전 2 블록이 등장한 뒤에는 구조 검증에서 하위 버전을 거부한다.
func verifyLegacyConsensusEvidence(lb LowerBlock) error {
	participants := consensusParticipants()
	required := quorumSizeFor(len(participants))
	if len(lb.Signatures) < required {
		return fmt.Errorf("기존 PBFT 서명 부족: %d/%d", len(lb.Signatures), required)
	}
	digest, err := hex.DecodeString(lb.BlockHash)
	if err != nil || len(digest) == 0 {
		return fmt.Errorf("기존 PBFT 블록 해시가 올바르지 않습니다: %q", lb.BlockHash)
	}
	used := make(map[string]bool, len(participants))
	valid := 0
	for _, signature := range lb.Signatures {
		for _, participant := range participants {
			if used[participant] {
				continue
			}
			publicKey, ok := pbftPublicKeyFor(participant)
			if ok && verifyECDSA(publicKey, digest, signature) {
				used[participant] = true
				valid++
				break
			}
		}
	}
	if valid < required {
		return fmt.Errorf("기존 PBFT 유효 서명 부족: %d/%d", valid, required)
	}
	log.Printf("[PBFT][기존 형식 검증] 블록 #%d의 서명 %d개를 확인했습니다. (정족수=%d)", lb.Index, valid, required)
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
func popPending() []ClinicRecord {
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
