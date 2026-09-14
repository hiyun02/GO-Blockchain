# 계층형 HotStuff 블록체인

상위체인 `gov`와 하위체인 `hos`가 모두 Basic HotStuff의 `PROPOSE → PREPARE → PRE-COMMIT → COMMIT → DECIDE` 절차로 블록을 확정합니다. 각 블록에는 세 단계 QC와 서명자·참여자 스냅샷이 저장되며, 체인 동기화 때 QC를 다시 검증합니다.

## 폴더 구조

- `gov`: Hos Merkle root 앵커를 수집하는 HotStuff 상위체인
- `hos`: 진료 레코드를 처리하고 확정 root를 Gov에 앵커링하는 HotStuff 하위체인
- `compose.yaml`: Gov 1개, Hos 2개 로컬 검증 구성
- `verify-benchmark.ps1`: `../py_exper/benchmark.py` 실행 및 양쪽 QC 검증

## 로컬 Docker 검증

```powershell
cd C:\Workspace\GO-Blockchain\HotStuff
docker compose down -v
.\verify-benchmark.ps1
```

기본 포트는 Gov `5000`, Hos 부트노드 `7000`, Hos 복제 노드 `7001`입니다. Hos는 2노드이므로 각 QC에 2개 서명이 필요하며, 단일 Gov는 각 QC에 1개 서명이 필요합니다.

벤치마크 요청 수를 지정하거나 기존 블록을 전수 재검증할 수 있습니다.

```powershell
.\verify-benchmark.ps1 -RequestCount 401 -SkipBuild
.\verify-benchmark.ps1 -SkipBuild -ValidateOnly
```

## 이미지

```text
hiyun2002/hos-node:hotstuff
hiyun2002/gov-node:hotstuff
```
