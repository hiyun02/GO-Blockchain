package cp

////////////////////////////////////////////////////////////////////////////////
// Data Models (데이터 스키마)
//
//체인 간 교차 검증을 위해 필요한 최소 데이터 구조 정의
// - ContentRecord  : 콘텐츠 단위 메타데이터
// - LowerBlock     : CP 체인의 블록 구조 (Merkle Root 포함)
// - ContractData   : CP-OTT 간 계약 정보
// - UpperRecord    : OTT 체인에 저장되는 앵커 및 계약 스냅샷
// - UpperBlock     : OTT 체인의 블록 구조
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// 1. ContentRecord
// ------------------------------------------------------------
// 개별 콘텐츠에 대한 메타데이터를 정의.
// CP 체인에서는 콘텐츠 단위로 해시를 생성하여 Merkle 트리에 포함.
// OTT 체인에서는 이 해시를 통해 콘텐츠의 무결성을 검증.
////////////////////////////////////////////////////////////////////////////////

type ContentRecord struct {
	ContentID   string                 `json:"content_id"`     // 고유 ID
	Info        map[string]interface{} `json:"info,omitempty"` // 메타데이터 (제목, 설명, 카테고리 등)
	Fingerprint string                 `json:"fingerprint"`    // 컨텐츠 원본 무결성을 보장하는 해시값 (머클 트리 해싱을 위한 주요 필드)
	StorageAddr string                 `json:"storage_addr"`   // 저장 경로
	DRM         map[string]interface{} `json:"drm,omitempty"`  // (선택) DRM 관련 정보
	Timestamp   string                 `json:"timestamp"`      // 등록 시각
}

////////////////////////////////////////////////////////////////////////////////
// 2. ContractData (계약 정보)
// ------------------------------------------------------------
// CP와 OTT 간의 계약 내용을 정의.
// 이 정보는 OTT 체인에서 CP의 접근 정책을 검증할 때 사용됨.
// - 만료일(expiry_ts)
// - 허용 지역(regions)
// - 허용 콘텐츠 리스트(allowed_content_ids)
////////////////////////////////////////////////////////////////////////////////

type ContractData struct {
	CPID              string            `json:"cp_id"`               // CP 식별자
	ExpiryTimestamp   string            `json:"expiry_ts"`           // 계약 만료 시각
	Regions           []string          `json:"regions,omitempty"`   // 서비스 허용 지역
	AllowedContentIDs []string          `json:"allowed_content_ids"` // 허용된 콘텐츠 ID 목록
	Meta              map[string]string `json:"meta,omitempty"`      // 추가적인 계약 정보 (버전, 조건 등)
}

////////////////////////////////////////////////////////////////////////////////
// 3. UpperRecord (OTT 체인의 단일 앵커 레코드)
// ------------------------------------------------------------
// OTT 체인에서 하나의 CP에 대해 생성되는 앵커 및 계약 스냅샷 정보.
// - CPID: 콘텐츠 제공자 ID
// - ContractSnapshot: 계약 당시의 상태를 저장
// - LowerRoot: CP 체인에서 전달된 서명된 Merkle Root
// - AccessCatalog: 접근 가능한 콘텐츠 목록
// - AnchorTimestamp: 앵커가 제출된 시각
////////////////////////////////////////////////////////////////////////////////

type UpperRecord struct {
	CPID             string       `json:"cp_id"`             // 콘텐츠 제공자 ID
	ContractSnapshot ContractData `json:"contract_snapshot"` // 계약 상태 스냅샷
	LowerRoot        string       `json:"lower_root"`        // CP 체인에서 전달된 머클 루트 (서명 포함)
	AccessCatalog    []string     `json:"access_catalog"`    // 접근 가능한 콘텐츠 리스트
	AnchorTimestamp  string       `json:"anchor_ts"`         // 앵커가 제출된 시간
}

////////////////////////////////////////////////////////////////////////////////
// 4. UpperBlock (OTT 체인의 블록 구조)
// ------------------------------------------------------------
// OTT 체인에서 거버넌스 단위로 생성되는 블록.
// - 여러 CP의 UpperRecord를 포함할 수 있음.
// - 계약, 앵커, 정책 변경 등의 메타데이터를 포함.
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
