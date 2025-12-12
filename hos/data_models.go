package main

////////////////////////////////////////////////////////////////////////////////
// Data Models (데이터 스키마)
//
//체인 간 교차 검증을 위해 필요한 최소 데이터 구조 정의
// - ClinicRecord  : 진료 정보 메타데이터
// - LowerBlock    : Hos 체인의 블록 구조 (Merkle Root 포함)
// - ContractData  : Hos-Gov 간 계약 정보
// - AnchorRecord  : Gov 체인에 저장되는 앵커 및 계약 스냅샷
// - UpperBlock    : Gov 체인의 블록 구조
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// 1. ClinicRecord
// ------------------------------------------------------------
// 개별 진료 정보에 대한 메타데이터 정의.
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
// 2. ContractData (계약 정보)
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
// 3. AnchorRecord (Gov 체인의 단일 앵커 레코드)
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

////////////////////////////////////////////////////////////////////////////////
// 4. UpperBlock (Gov 체인의 블록 구조)
// ------------------------------------------------------------
// Gov 체인에서 거버넌스 단위로 생성되는 블록.
// - 여러 Hos의 AnchorRecord를 포함할 수 있음.
// - 계약, 앵커, 정책 변경 등의 메타데이터를 포함.
// - 난이도(difficulty)가 설정되어 있다면 PoW 형태로 블록 해시 봉인 가능.
////////////////////////////////////////////////////////////////////////////////

type UpperBlock struct {
	Index      int            `json:"index"`       // 블록 번호
	GovID      string         `json:"gov_id"`      // Gov 체인 식별자
	PrevHash   string         `json:"prev_hash"`   // 이전 블록의 해시
	Timestamp  string         `json:"timestamp"`   // 생성 시간 (RFC3339 형식)
	Records    []AnchorRecord `json:"records"`     // Hos 체인에서 제출한 AnchorRecord 목록
	MerkleRoot string         `json:"merkle_root"` // AnchorRecords 속 MerkleRoot들을 병합하여 계산한 상위 MerkleRoot
	Nonce      int            `json:"nonce"`       // PoW용 Nonce
	Difficulty int            `json:"difficulty"`  // 난이도
	BlockHash  string         `json:"block_hash"`  // 블록 전체 해시
}
