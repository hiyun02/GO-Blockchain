package main

////////////////////////////////////////////////////////////////////////////////
// Data Models (데이터 스키마)
//
//체인 간 교차 검증을 위해 필요한 최소 데이터 구조 정의
// - ClinicRecord  : 진료 정보 단위 메타데이터
// - LowerBlock     : Hos 체인의 블록 구조 (Merkle Root 포함)
// - ContractData   : Hos-Gov 간 계약 정보
// - AnchorRecord    : Gov 체인에 저장되는 앵커 및 계약 스냅샷
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// 1. ClinicRecord
// ------------------------------------------------------------
// 개별 진료 정보에 대한 메타데이터를 정의.
// Hos 체인에서는 진료 정보 단위로 해시를 생성하여 Merkle 트리에 포함.
// Gov 체인에서는 이 해시를 통해 진료 정보의 무결성을 검증.
////////////////////////////////////////////////////////////////////////////////

type ClinicRecord struct {
	ClinicID  string                 `json:"clinic_id"`            // 병원 내 진료기록 ID
	Info      map[string]interface{} `json:"info,omitempty"`       // 진료 정보
	PatientID string                 `json:"patient_id"`           // 환자 ID
	PrescCode string                 `json:"presc_code"`           // 처방 코드
	ClinicHis map[string]interface{} `json:"clinic_his,omitempty"` // 진료 기록
	Timestamp string                 `json:"timestamp"`            // 생성 시각
}

////////////////////////////////////////////////////////////////////////////////
// 2. LowerBlock (Hos 체인 블록 구조)
// ------------------------------------------------------------
// Hos(clinic Provider) 체인에서 생성되는 블록 단위 구조체.
// 하나의 블록은 여러 ClinicRecord를 포함하고,
// 그 해시들을 기반으로 Merkle Root를 계산하여 블록 헤더에 저장.
////////////////////////////////////////////////////////////////////////////////

type LowerBlock struct {
	Index      int            `json:"index"`       // 블록 번호
	HosID      string         `json:"hos_id"`      // Hos 체인 식별자
	PrevHash   string         `json:"prev_hash"`   // 이전 블록의 해시
	Timestamp  string         `json:"timestamp"`   // 생성 시간 (RFC3339 형식)
	Entries    []ClinicRecord `json:"entries"`     // 블록 내 진료 정보 목록
	MerkleRoot string         `json:"merkle_root"` // Entries의 해시 기반 머클루트
	Nonce      int            `json:"nonce"`       // PoW 성공 시점의 Nonce
	Difficulty int            `json:"difficulty"`  // 난이도 (ex: 4 => "0000"으로 시작)
	BlockHash  string         `json:"block_hash"`  // 블록 전체 해시 (헤더 기준)
	Elapsed    float32        `json:"elapsed"`     // 채굴 소요 시간
	LeafHashes []string       `json:"leaf_hashes"` // Merkle Proof 재현을 위한 해시값 모음
}

////////////////////////////////////////////////////////////////////////////////
// 3. ContractData (계약 정보)
// ------------------------------------------------------------
// Hos와 Gov 간의 계약 내용을 정의.
// 이 정보는 Gov 체인에서 Hos의 접근 정책을 검증할 때 사용됨.
// - 만료일(expiry_ts)
// - 허용 지역(regions)
// - 허용 진료 정보 리스트(allowed_clinic_ids)
////////////////////////////////////////////////////////////////////////////////

type ContractData struct {
	HosID            string            `json:"hos_id"`             // Hos 식별자
	ExpiryTimestamp  string            `json:"expiry_ts"`          // 계약 만료 시각
	Regions          []string          `json:"regions,omitempty"`  // 서비스 허용 지역
	AllowedClinicIDs []string          `json:"allowed_clinic_ids"` // 허용된 진료 정보 ID 목록
	Meta             map[string]string `json:"meta,omitempty"`     // 추가적인 계약 정보 (버전, 조건 등)
}

////////////////////////////////////////////////////////////////////////////////
// 4. AnchorRecord (Gov 체인의 단일 앵커 레코드)
// ------------------------------------------------------------
// Gov 체인에서 하나의 Hos에 대해 생성되는 앵커 및 계약 스냅샷 정보.
// - HosID: 진료 정보 제공자 ID
// - ContractSnapshot: 계약 당시의 상태를 저장
// - LowerRoot: Hos 체인에서 전달된 서명된 Merkle Root
// - AccessCatalog: 접근 가능한 진료 정보 목록
// - AnchorTimestamp: 앵커가 제출된 시각
////////////////////////////////////////////////////////////////////////////////

type AnchorRecord struct {
	HosID            string       `json:"hos_id"`            // 진료 정보 제공자 ID
	ContractSnapshot ContractData `json:"contract_snapshot"` // 계약 상태 스냅샷
	LowerRoot        string       `json:"lower_root"`        // Hos 체인에서 전달된 머클 루트 (서명 포함)
	AccessCatalog    []string     `json:"access_catalog"`    // 접근 가능한 진료 정보 리스트
	AnchorTimestamp  string       `json:"anchor_ts"`         // 앵커가 제출된 시간
}
