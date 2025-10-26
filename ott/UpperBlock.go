package main

import "time"

////////////////////////////////////////////////////////////////////////////////
// UpperBlock (OTT 체인의 블록 구조)
// ------------------------------------------------------------
// OTT 체인에서 거버넌스 단위로 생성되는 블록.
// - 여러 CP의 UpperRecord(계약+앵커 스냅샷)를 묶어 확정
// - 계약, 앵커, 정책 변경 등의 메타데이터를 포함.
// - 블록 해시는 헤더 서브셋만 JSON 직렬화 -> SHA-256(hex)
//   * Lower와의 차이: Lower는 MerkleRoot, Upper는 RecordsDigest(Records 요약)
// - 난이도(difficulty)가 설정되어 있다면 PoW 형태로 블록 해시 봉인 가능.
////////////////////////////////////////////////////////////////////////////////

type UpperBlock struct {
	Index     int           `json:"index"`      // 블록 번호
	PrevHash  string        `json:"prev_hash"`  // 이전 블록의 해시
	Timestamp string        `json:"timestamp"`  // 블록 생성 시간
	Records   []UpperRecord `json:"records"`    // 포함된 UpperRecord 리스트
	Nonce     int           `json:"nonce"`      // (선택) PoW 난수
	BlockHash string        `json:"block_hash"` // 블록 전체의 해시
}

// 제네시스 상수 (CP와 대칭)
const (
	genesisTimestamp = "1971-01-01T00:00:00Z"                                             // 재현성 보장
	prevHashZeros    = "0000000000000000000000000000000000000000000000000000000000000000" // 64자리 0
)

// Records 전체를 캐논 JSON → SHA-256(hex)로 요약 (Upper 전용)
func digestUpperRecords(records []UpperRecord) string {
	return sha256Hex(jsonCanonical(records))
}

// 제네시스 블록 생성 (Upper는 cp_id 없음)
func createGenesisBlock() UpperBlock {
	genesis := UpperBlock{
		Index:     0,
		PrevHash:  prevHashZeros,
		Timestamp: genesisTimestamp,
		Records:   []UpperRecord{},
		Nonce:     0,
	}
	genesis.BlockHash = genesis.computeHash()
	return genesis
}

// 해시 계산: 헤더 서브셋만 포함 (Lower와 동일한 패턴, 단 RecordsDigest 사용)
func (b UpperBlock) computeHash() string {
	hdr := struct {
		Index         int    `json:"index"`
		PrevHash      string `json:"prev_hash"`
		Timestamp     string `json:"timestamp"`
		RecordsDigest string `json:"records_digest"`
	}{
		Index:         b.Index,
		PrevHash:      b.PrevHash,
		Timestamp:     b.Timestamp,
		RecordsDigest: digestUpperRecords(b.Records),
	}
	return sha256Hex(jsonCanonical(hdr))
}

// 신규 블록 생성 (prev 연결 + 헤더 해시)
func newUpperBlock(prev UpperBlock, records []UpperRecord) UpperBlock {
	nb := UpperBlock{
		Index:     prev.Index + 1,
		PrevHash:  prev.BlockHash,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Records:   records,
		Nonce:     0,
	}
	nb.BlockHash = nb.computeHash()
	return nb
}
