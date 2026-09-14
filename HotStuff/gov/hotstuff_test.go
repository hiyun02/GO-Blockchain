package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestQuorumSizeFor(t *testing.T) {
	tests := []struct {
		n, want int
	}{{1, 1}, {4, 3}, {7, 5}, {10, 7}}
	for _, test := range tests {
		if got := quorumSizeFor(test.n); got != test.want {
			t.Fatalf("quorumSizeFor(%d)=%d, want %d", test.n, got, test.want)
		}
	}
}

func TestQuorumCertificateVerification(t *testing.T) {
	cleanup := setupHotStuffTestState(t)
	defer cleanup()

	participants := []string{"node-a", "node-b", "node-c", "node-d"}
	privateKeys := map[string]string{}
	for _, node := range participants {
		privateKey, publicKey := generateTestKeyPair(t)
		privateKeys[node] = privateKey
		if node == self {
			if err := putMeta("meta_gov_privkey", privateKey); err != nil {
				t.Fatal(err)
			}
			if err := putMeta("meta_gov_pubkey", publicKey); err != nil {
				t.Fatal(err)
			}
		} else {
			peerPubKeys[node] = publicKey
		}
	}

	qc := QuorumCertificate{
		View: 3, Phase: PhasePrepare, BlockHash: strings.Repeat("a", 64),
		Leader: "node-a", Participants: participants, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	digest := hotStuffVoteDigest(qc.View, qc.Phase, qc.BlockHash, qc.Leader, qc.Participants)
	for _, node := range participants[:3] {
		qc.Signatures = append(qc.Signatures, HotStuffSignature{
			Voter: node, Signature: makeAnchorSignature(privateKeys[node], hex.EncodeToString(digest), ""),
		})
	}
	if err := verifyQuorumCertificate(qc); err != nil {
		t.Fatalf("3-of-4 QC should verify: %v", err)
	}

	insufficient := qc
	insufficient.Signatures = insufficient.Signatures[:2]
	if err := verifyQuorumCertificate(insufficient); err == nil {
		t.Fatal("2-of-4 QC must be rejected")
	}

	tamperedMembership := qc
	tamperedMembership.Participants = []string{"node-a", "node-b", "node-c"}
	if err := verifyQuorumCertificate(tamperedMembership); err == nil {
		t.Fatal("membership-tampered QC must be rejected because membership is signed")
	}

	tamperedHash := qc
	tamperedHash.BlockHash = strings.Repeat("b", 64)
	if err := verifyQuorumCertificate(tamperedHash); err == nil {
		t.Fatal("hash-tampered QC must be rejected")
	}
}

func TestSingleNodeHotStuffEndToEnd(t *testing.T) {
	cleanup := setupHotStuffTestState(t)
	defer cleanup()

	if _, err := newUpperChain("Gov-Test"); err != nil {
		t.Fatal(err)
	}
	ensureKeyPair()

	mux := http.NewServeMux()
	mux.HandleFunc("/hotstuff/propose", handleHotStuffProposal)
	mux.HandleFunc("/hotstuff/vote", handleHotStuffVote)
	mux.HandleFunc("/hotstuff/qc", handleHotStuffQC)
	server := httptest.NewServer(mux)
	defer server.Close()

	self = strings.TrimPrefix(server.URL, "http://")
	boot = self
	isBoot.Store(true)
	currentView.Store(0)

	block := createProposedBlock([]AnchorRecord{{
		HosID: "Hos-Test-A", LowerRoot: strings.Repeat("1", 64),
		AnchorTimestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}})
	consensusInProgress.Store(true)
	launchHotStuffView(block, "통합 테스트")

	deadline := time.Now().Add(5 * time.Second)
	var firstBlock UpperBlock
	for time.Now().Before(deadline) {
		if height, ok := getLatestHeight(); ok && height == 1 {
			committed, err := getBlockByIndex(1)
			if err != nil {
				t.Fatal(err)
			}
			if committed.HotStuff == nil {
				t.Fatal("committed block has no HotStuff proof")
			}
			if err := verifyConsensusEvidence(committed); err != nil {
				t.Fatalf("persisted HotStuff proof is invalid: %v", err)
			}
			if committed.HotStuff.PrepareQC.Phase != PhasePrepare ||
				committed.HotStuff.PreCommitQC.Phase != PhasePreCommit ||
				committed.HotStuff.CommitQC.Phase != PhaseCommit {
				t.Fatal("persisted QC chain has wrong phase ordering")
			}
			firstBlock = committed
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if firstBlock.BlockHash == "" {
		t.Fatal("HotStuff consensus did not commit a block before timeout")
	}

	second := createProposedBlock([]AnchorRecord{{
		HosID: "Hos-Test-B", LowerRoot: strings.Repeat("2", 64),
		AnchorTimestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}})
	consensusInProgress.Store(true)
	launchHotStuffView(second, "잠금 QC 연장 테스트")
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if height, ok := getLatestHeight(); ok && height == 2 {
			committed, err := getBlockByIndex(2)
			if err != nil {
				t.Fatal(err)
			}
			if committed.PrevHash != firstBlock.BlockHash {
				t.Fatal("second block does not extend the locked/committed block")
			}
			if committed.HotStuff == nil || committed.HotStuff.View <= firstBlock.HotStuff.View {
				t.Fatal("second block did not advance the HotStuff view")
			}
			if err := verifyConsensusEvidence(committed); err != nil {
				t.Fatalf("second block proof is invalid: %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("HotStuff consensus did not commit the second block before timeout")
}

func setupHotStuffTestState(t *testing.T) func() {
	t.Helper()
	testRoot := t.TempDir()
	blockHistoryPath = filepath.Join(testRoot, "block_history.txt")
	initDB(filepath.Join(testRoot, "db"))
	self = "node-a"
	boot = self
	peers = nil
	peerPubKeys = make(map[string]string)
	hotStuffStates = make(map[uint64]*hotStuffViewState)
	voted = make(map[string]string)
	highQC = nil
	lockedQC = nil
	activeBlock = nil
	activeStarted = time.Time{}
	consensusInProgress.Store(false)
	currentView.Store(0)
	ch = &UpperChain{govID: "Gov-Test", pending: []AnchorRecord{}}
	return func() {
		consensusInProgress.Store(false)
		closeDB()
		blockHistoryPath = "block_history.txt"
	}
}

func generateTestKeyPair(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
}

func TestConsensusParticipantsAreSortedAndUnique(t *testing.T) {
	self = "node-c"
	peers = []string{"node-b", "node-a", "node-c", "node-b"}
	got := consensusParticipants()
	want := []string{"node-a", "node-b", "node-c"}
	if !sort.StringsAreSorted(got) || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("participants=%v, want %v", got, want)
	}
}

func TestLockedQCSafetyAndNoDoubleVote(t *testing.T) {
	lockedQC = &QuorumCertificate{View: 5, BlockHash: "locked-block"}
	defer func() { lockedQC = nil }()

	if !safeToVote(UpperBlock{BlockHash: "locked-block"}, nil) {
		t.Fatal("re-proposal of the locked block must be safe")
	}
	if !safeToVote(UpperBlock{BlockHash: "child", PrevHash: "locked-block"}, nil) {
		t.Fatal("a child extending the locked block must be safe")
	}
	conflict := UpperBlock{BlockHash: "conflict", PrevHash: "other"}
	if safeToVote(conflict, nil) {
		t.Fatal("conflicting proposal without a higher QC must be rejected")
	}
	if !safeToVote(conflict, &QuorumCertificate{View: 6, BlockHash: "conflict"}) {
		t.Fatal("a conflicting proposal justified by a higher QC should unlock safely")
	}

	voted = make(map[string]string)
	if !recordVote(7, PhasePrepare, "block-a") {
		t.Fatal("first vote should be recorded")
	}
	if recordVote(7, PhasePrepare, "block-b") {
		t.Fatal("a node must not vote for two block hashes in the same view and phase")
	}
}
