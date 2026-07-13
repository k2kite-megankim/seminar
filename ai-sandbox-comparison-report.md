<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# AI 에이전트 샌드박스 보안 비교 보고서

**작성일:** 2026-07-13 (소스 기준: NemoClaw main, nono v0.67.1, srt v0.0.64)
**목적:** AI 샌드박스 솔루션 자체 구현 또는 오픈소스 포크 검토를 위한 기술·보안 비교

---

## 개요

AI를 제품이나 인프라에 도입할 때 공통된 보안 문제가 발생한다. AI가 코드를 실행하거나 도구를 호출할 때 **파일시스템, 네트워크, 크리덴셜**에 무제한 접근을 허용하면 데이터 유출, 내부망 침투, 권한 상승 위험이 생긴다.

이 보고서는 **기업 에이전트형** 샌드박스에 집중한다:

| 구분 | 설명 | 핵심 요구사항 |
|------|------|-------------|
| **기업 에이전트형** | 사내 AI 에이전트가 인프라·크리덴셜에 접근 시 격리 | 강한 보안, 크리덴셜 보호, 감사 로그, 정책 관리 |

이 보고서의 목적은 **자체 구현과 오픈소스 포크 중 어떤 경로가 현실적인가**를 판단하는 것이다. 마지막 섹션에서 각 솔루션의 포크 적합성을 평가한다.

---

## 1. 격리 기술 기반 비교

### 1.1 격리 기술 계층

```
강도 높음 ──────────────────────────────────── 강도 낮음

Firecracker/Kata     gVisor          OS 프리미티브      Docker 컨테이너
  (microVM)       (유저스페이스 커널)  (Landlock/cap)    (네임스페이스)
    │                  │                  │                  │
전용 커널 + VM       syscall 인터셉트    커널 직접 강제      공유 커널
콜드 스타트 ~100ms  콜드 스타트 빠름    컨테이너 없이 가능  가장 가벼움
가장 강한 격리       중간 격리           경량 프로세스 격리  신뢰 코드에만 적합
```

| 기술 | 격리 방식 | 콜드 스타트 | 오버헤드 | 멀티테넌트 | 비고 |
|------|----------|------------|---------|-----------|------|
| **Firecracker microVM** | 전용 경량 VM | ~100-200ms | 낮음 | 우수 | AWS 개발, E2B 사용 |
| **Kata Containers** | OCI 호환 VM | ~150-300ms | 중간 | 우수 | CNCF 프로젝트 |
| **gVisor** | 유저스페이스 커널 | 빠름 | I/O 10-30% | 우수 | Google 개발, syscall 재구현 |
| **Landlock + capabilities** | OS 커널 직접 | 없음 | 거의 없음 | 프로세스 단위 | 컨테이너 불필요, NemoClaw/nono 사용 |
| **Docker (일반)** | 네임스페이스/cgroup | 빠름 | 낮음 | 보통 | 신뢰 코드에만 적합 |

> **격리 기술과 에이전트 보안은 별개다.** microVM/gVisor는 커널 탈출을 막지만, 크리덴셜 유출·프롬프트 인젝션·공급망 공격은 격리 기술과 무관하게 별도 방어가 필요하다.

### 1.2 라이선스 현황

| 솔루션 | 라이선스 | 비고 |
|--------|---------|------|
| NemoClaw | Apache-2.0 | 오픈소스 |
| nono | Apache-2.0 | 오픈소스 |
| Anthropic srt | MIT | 오픈소스 |
| Microsoft AGT | MIT | 오픈소스 |

---

## 2. 기업 AI 에이전트 샌드박스

### 2.1 NVIDIA NemoClaw + OpenShell

**GitHub:** NVIDIA/NemoClaw, NVIDIA/OpenShell · **라이선스:** Apache-2.0
**격리:** Docker 컨테이너 + Landlock + Linux capabilities
**호스트 OS:** macOS ✓ (Docker Desktop/Colima) / Linux ✓ / Windows WSL2 ✓
**샌드박스 OS:** Linux (항상 — Landlock·capabilities는 컨테이너 내부에서 동작)

**5개 보안 레이어:**

| 레이어 | 기술 | 보호 대상 |
|--------|------|----------|
| 네트워크 | deny-by-default + 바이너리 스코프 + L7 검사 | 데이터 유출, 내부망 침투 |
| 파일시스템 | Landlock LSM + read-only 마운트 + shields up | 설정 변조, 민감 파일 접근 |
| 프로세스 | 10개 capability drop + No-New-Privileges + ulimit | 권한 상승, 포크 폭탄 |
| 크리덴셜 | 3모드 리댁션 + 스트리핑 + 메모리 스캐너 | API 키 유출 |
| 추론 격리 | inference.local 게이트웨이 | AI API 키 에이전트로부터 격리 |

**레이어별 격리 vs 에이전트 보안 분류:**

> **격리(Isolation):** 컨테이너를 외부로부터 분리 — 일반 보안 도구도 일부 제공
> **에이전트 보안(Agent Security):** AI의 행동 자체를 제어 — NemoClaw/nono만의 영역

| 레이어 | 기능 | 격리 | 에이전트 보안 | 비고 |
|--------|------|:----:|:------------:|------|
| **1. 네트워크** | deny-by-default + 허용목록 | ✓ | | 일반 방화벽도 제공 |
| | 바이너리 스코프 (실행 주체 검증) | | ✓ | NemoClaw 고유 — 어떤 바이너리가 보내는지 |
| | L7 HTTP 요청 검사 | | ✓ | 요청 내용까지 제어 |
| | DNS 핀닝 (리바인딩 방어) | | ✓ | AI 유도 DNS 조작 방어 |
| **2. 파일시스템** | Landlock 디렉터리 접근 제한 | ✓ | | Docker 유사 기능 |
| | read-only 마운트 | ✓ | | 일반 컨테이너 기술 |
| | **Shields Up** (설정 변조 방어) | | ✓ | 프롬프트 인젝션 → 설정 변조 방어 |
| **3. 프로세스** | capabilities 10개 제거 | ✓ | | 프로세스 권한 최소화 |
| | No-New-Privileges | ✓ | | 실행 중 권한 상승 차단 |
| | ulimit (프로세스/파일 수) | ✓ | | 포크 폭탄 방어 |
| **4. 크리덴셜** | 3모드 리댁션 (출력 마스킹) | | ✓ | AI 출력에서 키 자동 제거 |
| | 메모리 스캐너 | | ✓ | AI가 메모리에서 키 읽는 것 감지 |
| | inference.local 분리 | | ✓ | AI가 API 키를 볼 수 없는 구조 |
| **5. 추론 격리** | inference.local 게이트웨이 | | ✓ | 승인되지 않은 LLM 연결 차단 |

```
레이어 1 (네트워크)    ██ 격리  ████████ 에이전트 보안
레이어 2 (파일시스템)  ████ 격리  ████ 에이전트 보안 (Shields Up)
레이어 3 (프로세스)    ████████ 격리만  (에이전트 보안 없음)
레이어 4 (크리덴셜)    ████████ 에이전트 보안만  (격리 없음)
레이어 5 (추론 격리)   ████████ 에이전트 보안만  (격리 없음)
```

> **핵심:** E2B·gVisor 등 격리 전문 솔루션은 레이어 2·3(격리)만 가진 셈이다.
> NemoClaw는 거기에 레이어 1 바이너리 스코프, 레이어 4 크리덴셜 보호, 레이어 5 추론 격리를 추가한다.
> **AI를 가두는 것(격리)과 AI가 하는 행동을 제어하는 것(에이전트 보안)은 별개의 문제다.**

**보안 강점:** 바이너리 스코프 네트워크 제어, shields up 설정 잠금, 추론 크리덴셜 완전 분리
**보안 한계:** Docker 컨테이너 기반(microVM 수준 아님), OpenShell 0.0.44 고정 의존
**적합:** NVIDIA 인프라 상시 AI 에이전트

---

### 2.2 nolabs-ai nono

**GitHub:** github.com/nolabs-ai/nono · **라이선스:** Apache-2.0 · **상태:** Alpha (v0.67.1, 2026-07-06)
**격리:** OS 프리미티브 (Landlock + Seatbelt) — 컨테이너 불필요
**호스트 OS:** Linux ✓ (Landlock) / macOS ✓ (Seatbelt) / Windows △ (WSL2 경유)

**Sigstore 창시자 Luke Hinds(前 Red Hat Principal Security Engineer)가 창업한 nolabs가 만든** 에이전트 샌드박스. OpenSSF Best Practices 인증 취득. NOGENT.md 기반으로 설계된 Rust 워크스페이스.

**핵심 보안 기능:**
- Landlock (Linux) + Seatbelt (macOS) — Docker 불필요
- Sigstore 기반 공급망 보안 (프로파일 서명 검증)
- Phantom Token — 에이전트가 관리 프록시 경유 증명
- zeroize — 크리덴셜 메모리 사용 후 즉시 0 덮어쓰기
- Merkle tree 기반 파일 변경 Rollback
- append-only 감사 원장
- DNS 단일 해석 (DNS 리바인딩 방어)
- 바이너리 canonical path + inode + digest 검증
- OAuth 캡처 보안 경계 강화 (v0.67.0)
- macOS Seatbelt: 신뢰할 수 없는 규칙 자동 제거 — 에이전트가 삽입한 unsafe_macos_seatbelt_rules 무력화 (v0.67.0)
- Trust policy predicate — nono 정책과 외부 JSON 혼동 방지 (v0.67.0)
- AWS SigV4 프록시 서명 지원 (v0.67.0)

**추가 기능 (v0.67.x):** 서명된 프로파일 레지스트리(registry.nono.sh) — 에이전트별 보안 프로파일을 커뮤니티와 공유

**최신 패치 (v0.67.1, commit ac5ccd7):** `PR_SET_CHILD_SUBREAPER` 추가 — 에이전트가 고아 프로세스(daemonized/orphaned descendants)를 생성할 때 supervisor 감시 계층이 끊기는 버그 수정. Yama `ptrace_scope=1`이 적용된 기업 배포 환경에서 seccomp-notify 중재가 누락되는 문제.

**보안 강점:** 공급망 보안(Sigstore), 크로스플랫폼, OpenSSF Best Practices 인증, 가장 완성도 높은 보안 설계
**보안 한계:** Alpha (v1.0 릴리즈 준비 중, 3rd-party 감사 미완료), Linux에서 프롬프트 인젝션 설정 잠금 없음, Windows 미지원
**적합:** 공급망 보안 중시, Docker 없이 격리, macOS 지원

---

### 2.3 Anthropic sandbox-runtime (srt)

**GitHub:** github.com/anthropic-experimental/sandbox-runtime · **라이선스:** MIT · **상태:** Beta (v0.0.64)
**격리:** OS 프리미티브 (`sandbox-exec` on macOS, `bubblewrap` on Linux)
**호스트 OS:** Linux ✓ / macOS ✓ / Windows △ (WFP, alpha)
**설치:** `npm install -g @anthropic-ai/sandbox-runtime`

Claude Code 세션과 MCP 서버 격리용 경량 래퍼.

**핵심 보안 기능:**
- `sandbox-exec`(macOS) / `bubblewrap`(Linux) OS 프리미티브 (컨테이너 불필요)
- 네트워크 허용목록 — 도메인 단위 HTTP/HTTPS 차단
- 파일시스템 read/write 제어 — 디렉터리·파일 단위
- Unix 소켓 접근 제어
- TLS MITM 기반 L7 HTTP 요청 검사 옵션
- `filterRequest` 콜백 — 교체 가능한 정책 훅
- x64/arm64 seccomp BPF 지원
- **환경변수 크리덴셜 마스킹 (v0.0.64)** — `buildMaskedEnvVars` + `SentinelRegistry`: 샌드박스에 전달하는 환경변수를 실제 값 대신 센티넬 토큰으로 교체. 프록시가 허용된 호스트로 요청이 나갈 때만 센티넬→실제값 치환. `extract` 옵션으로 DATABASE_URL 같은 복합 값에서 비밀번호 부분만 선택적으로 마스킹 가능
- **Linux 샌드박스 위반 모니터 (v0.0.64)** — `startLinuxSandboxViolationMonitor`: Linux에서 파일시스템 syscall(openat, unlinkat 등) 위반을 실시간 감지·리포트
- 심볼릭 링크 deny 경로 우회 방어 회귀 강화 (v0.0.64)

#### Windows 네이티브 지원 (v0.0.64, alpha)

비교 대상 중 **유일한 네이티브 Windows 샌드박스**다. WSL2 불필요.

| 구성 요소 | 역할 |
|----------|------|
| `srt-win.exe` (Rust 바이너리) | UAC 한 번으로 `srt-sandbox` 로컬 유저 계정 생성 |
| **WFP (Windows Filtering Platform)** | 커널 레벨 네트워크 필터 — `srt-sandbox` 유저 SID 기반 적용 |
| 2단 프로세스 구조 | `broker → CreateProcessWithLogonW(runner) → restricted-token child` |
| 파일시스템 ACE | `srt-sandbox` SID에 허용 경로를 additive grant로 지정 |

**nono와의 차이:** nono는 Windows 지원 없음(WSL2 경유만 가능). srt는 WFP 필터가 유저 SID 기반이라 AI가 새 프로세스를 생성해 네트워크 우회를 시도해도 자식이 동일 SID를 상속하거나 SID가 달라 필터에 걸린다 (surrogate-spawn 공격 차단).

**한계:** alpha 상태. 기업 프로덕션 전 충분한 검증 필요.

**보안 강점:** 경량, 크로스플랫폼(macOS/Linux/Windows 네이티브), Claude 통합, v0.0.64에서 환경변수 크리덴셜 마스킹 + Linux 위반 모니터 추가
**보안 한계:** 환경변수 마스킹은 부분적(NemoClaw의 inference.local처럼 AI가 키 자체를 볼 수 없는 구조는 아님), SSRF 방어 없음, 공급망 보안 없음, Windows sandboxing은 alpha
**적합:** Claude Code / MCP 서버 격리; Windows 엔터프라이즈 환경

---

### 2.4 Microsoft Agent Governance Toolkit

**GitHub:** github.com/microsoft/agent-governance-toolkit · **라이선스:** MIT · **출시:** 2026년 4월
**호스트 OS:** 모든 OS (Python/TypeScript/.NET SDK)

OWASP Agentic Top 10 전체 커버 런타임 거버넌스 툴킷. **격리 자체를 제공하지 않음** — 다른 샌드박스와 함께 사용해야 의미가 있다.

**핵심 기능:** 서브밀리초 정책 강제, LangChain/CrewAI/Google ADK 등 프레임워크 무관, EU AI Act / Colorado AI Act 대응

**보안 강점:** OWASP Agentic Top 10 전체(10/10), 컴플라이언스, 프레임워크 무관
**보안 한계:** OS/커널 격리 없음, 크리덴셜 격리 없음, 네트워크 실제 차단 없음
**적합:** 기존 AI 프레임워크에 거버넌스 레이어 추가

---

## 3. 보안 비교

### 3.1 기업 에이전트형

| 기능 | NemoClaw | nono | srt | MS AGT |
|------|---------|------|-----|--------|
| **격리 방식** | Docker + Landlock | OS 프리미티브 | OS 프리미티브 | 없음 |
| **커널 탈출 방어** | △ | △ | △ | ✗ |
| **네트워크 정책** | ✓ 바이너리 스코프 | ✓ 허용목록 | △ | △ 정책만 |
| **SSRF / DNS 리바인딩** | ✓ | ✓ | ✗ | ✗ |
| **크리덴셜 격리** | ✓ 게이트웨이 | ✓ Phantom Token | △ env var 마스킹 (v0.0.64) | ✗ |
| **메모리 시크릿 스캐너** | ✓ | ✓ zeroize | △ 위반 모니터 (v0.0.64) | ✗ |
| **프롬프트 인젝션 방어** | ✓ shields up | ✗ | ✗ | ✓ 정책 |
| **공급망 보안** | ✓ SHA256 핀닝 | ✓ Sigstore | △ npm | ✗ |
| **감사 로그** | ✓ append-only | ✓ append-only | ✗ | ✓ |
| **바이너리 하이재킹 방어** | ✓ | ✓ | ✗ | △ |
| **권한 상승 방어** | ✓ 10 caps + NNP | ✓ | △ | ✗ |
| **호스트 OS** | macOS/Linux/WSL2 | macOS/Linux/△WSL2 | 모든 OS | 모든 OS |
| **오픈소스** | ✓ Apache-2.0 | ✓ Apache-2.0 | ✓ MIT | ✓ MIT |
| **상태** | 프로덕션 | Alpha | Beta | 프로덕션 |

### 3.2 위협 대응 매트릭스 (기업 에이전트형)

> ✓ 방어 / △ 부분 방어 / ✗ 미방어

| 공격 벡터 | NemoClaw | nono | srt | MS AGT | 방어 기법 비고 |
|----------|---------|------|-----|--------|--------------|
| **커널/컨테이너 탈출** | △ | △ | △ | ✗ | NemoClaw·nono·srt: caps drop + NNP. microVM 수준 아님 |
| **DNS 리바인딩 / SSRF** | ✓ | ✓ | ✗ | ✗ | NemoClaw: ssrf.ts URL검증→DNS핀닝. nono: DNS 단일 해석 후 검증된 IP만 사용 |
| **API 키 직접 유출** | ✓ | ✓ | △ | ✗ | NemoClaw: inference.local 게이트웨이 분리. nono: Phantom Token(관리 프록시 경유 증명). srt: env var 센티넬 마스킹(v0.0.64) — 샌드박스가 실제 키 대신 토큰을 받음. 단, AI 모델 자체가 키를 볼 수 없게 하는 구조(inference.local)는 없음 |
| **메모리 내 시크릿 탈취** | ✓ | ✓ | △ | ✗ | NemoClaw: before_tool_call 훅으로 Write/Edit 가로채기. nono: zeroize(메모리 0덮어쓰기). srt: Linux 위반 모니터(v0.0.64)로 파일시스템 syscall 실시간 감지 |
| **프롬프트 인젝션 → 설정 변조** | ✓ | △ | ✗ | ✓ | NemoClaw: shields up(chmod+chattr+i+SHA256). nono: macOS Seatbelt 신뢰할 수 없는 규칙 자동 제거(v0.67.0), Linux 미지원. MS AGT: Goal Hijacking 정책 강제 |
| **공급망 (악성 이미지/패키지)** | ✓ | ✓ | △ | ✗ | NemoClaw: SHA256 다이제스트 핀닝 + CI :latest 차단. nono: Sigstore 번들 서명 검증 |
| **내부망 침투** | ✓ | ✓ | △ | △ | NemoClaw: 바이너리 스코프(어떤 실행파일이 어느 도메인). nono: 허용목록 |
| **권한 상승** | ✓ | ✓ | △ | ✗ | NemoClaw: capsh 10개 + setpriv 5개 + No-New-Privileges. nono: capabilities 제한 |
| **포크 폭탄 / 리소스 고갈** | ✓ | ✓ | △ | ✗ | NemoClaw: ulimit -u 512 / -n 65536 |
| **바이너리 하이재킹 (PATH shadowing)** | ✓ | ✓ | ✗ | △ | NemoClaw: /proc/pid/exe + SHA256 + PATH 하드닝. nono: canonical path + inode + digest |
| **감사 기록 은닉** | ✓ | ✓ | ✗ | ✓ | NemoClaw: append-only JSONL shields-audit. nono: append-only 원장 |

**위협 대응 점수 (11개 기준, ✓=1점 / △=0.5점):**
NemoClaw **10** / nono **8** / MS AGT **4** / srt **4** (v0.0.64 기준 — API키·메모리 탈취 항목이 △로 상향)

> 점수가 높다고 모든 환경에 적합한 건 아니다. NemoClaw는 Linux 컨테이너 의존, nono는 Alpha 상태다.

---

## 4. 선택 가이드

```
AI 에이전트가 사내 시스템에 접근하는가?
    ├─ NVIDIA 인프라 사용?
    │       → NemoClaw + OpenShell
    ├─ 공급망 보안 + Docker 없이?
    │       → nono (Alpha, 감사 완료 후 권장)
    ├─ Claude Code / MCP 격리, 또는 Windows 환경 필수?
    │       → Anthropic srt
    └─ LangChain/CrewAI에 거버넌스 추가?
            → Microsoft AGT + 별도 격리
```

---

## 5. 자체 구현 vs 오픈소스 포크 검토

### 5.1 자체 구현의 현실

완성도 있는 에이전트 샌드박스를 처음부터 만드는 것은 매우 어렵다.

| 구현 영역 | 난이도 | 주요 위험 |
|----------|--------|----------|
| Landlock / Seatbelt 정책 설계 | 높음 | 잘못된 허용 규칙 → 격리 우회 |
| seccomp BPF 필터 | 높음 | 필터 오작성 → 커널 익스플로잇 가능 |
| DNS 핀닝 + SSRF 방어 | 중간 | TOCTOU 레이스 조건 |
| 크리덴셜 프록시 아키텍처 | 높음 | 타이밍 공격, 메모리 잔류 |
| 공급망 서명 검증 (Sigstore) | 중간 | 잘못된 신뢰 체인 구성 |
| append-only 감사 원장 | 낮음 | 무결성 검증 누락 |

**예상 공수:** 보안 엔지니어 3-4명 기준 6-12개월. 3rd-party 보안 감사까지 포함하면 추가 3-6개월.

**자체 구현이 유리한 경우:**
- 매우 특수한 격리 요구사항 (기존 솔루션이 맞지 않는 경우)
- 특정 하드웨어/OS에 강하게 최적화 필요
- 외부 의존성을 최소화해야 하는 규제 환경

### 5.2 포크 후보 평가

| 항목 | NemoClaw | nono | srt |
|------|---------|------|-----|
| **언어** | TypeScript | Rust | Rust |
| **코드베이스 규모** | 중간 | 중간 | 작음 |
| **보안 커버리지** | 10/11 | 8/11 | 4/11 (v0.0.64) |
| **라이선스** | Apache-2.0 | Apache-2.0 | MIT |
| **벤더 종속성** | NVIDIA/OpenShell 높음 | 없음 | Anthropic 중간 |
| **크로스플랫폼** | △ (샌드박스는 Linux) | ✓ Linux+macOS | ✓ |
| **커뮤니티 활성도** | NVIDIA 주도 | 초기 | Anthropic 주도 |
| **프로덕션 안정성** | ✓ | ✗ Alpha | △ Beta |
| **아키텍처 확장성** | 중간 | 높음 | 낮음 |
| **포크 난이도** | 중간 | 높음 (Rust 필요) | 낮음 |

### 5.3 시나리오별 포크 권고

**시나리오 A: 기업 AI 에이전트 보안 플랫폼 구축**

> **nono 포크 권고** (단, Alpha 상태 감안 필요)

nono는 현재 비교 대상 중 가장 완성도 높은 보안 아키텍처를 갖고 있다. Rust로 작성되어 메모리 안전성이 보장되며, NVIDIA 종속성이 없고 Linux + macOS 모두 지원한다. Sigstore, Phantom Token, Rollback, append-only 원장 등 핵심 보안 요소가 이미 설계되어 있다.

포크 시 주요 추가 작업:
- 프롬프트 인젝션 방어 (shields up 상당 기능)
- 웹 UI / 운영 도구
- 내부 인프라 연동 (SSO, SIEM 등)
- 3rd-party 보안 감사 완료 후 프로덕션 투입

**시나리오 B: 기존 AI 프레임워크에 보안 레이어만 추가**

> **MS Agent Governance Toolkit 도입 + nono 또는 srt 조합**

격리는 기존 인프라(Docker/K8s)가 담당하고, 거버넌스·컴플라이언스만 빠르게 올리고 싶다면 MS AGT가 가장 빠른 경로다.

### 5.4 공통 고려사항

어떤 경로를 선택하든 아래 항목은 자체 구현 또는 추가가 필요하다:

| 항목 | 이유 |
|------|------|
| 사내 SSO 통합 | 대부분 외부 IdP 지원이 없거나 설정 필요 |
| 크리덴셜 볼트 연동 (HashiCorp Vault 등) | 대부분 환경변수 또는 파일 기반 |
| 사내 SIEM/로그 시스템 연동 | 감사 로그 포맷 변환 |
| 내부 CA / TLS 정책 | TLS 인터셉트 시 내부 CA 신뢰 필요 |
| 규제 컴플라이언스 (개인정보보호법, 금융보안원 등) | 국내 규제는 대부분 미적용 |

---

## 6. 결론

| 상황 | 추천 | 핵심 이유 |
|------|------|----------|
| 기업 에이전트 보안 플랫폼 포크 | **nono** | 보안 설계 최우수, NVIDIA 종속 없음 |
| Windows 엔터프라이즈 환경 격리 | **srt** | 유일한 WFP 네이티브 Windows 샌드박스 |
| 거버넌스 레이어만 빠르게 | **MS AGT** | OWASP 전체 커버, 프레임워크 무관 |

**핵심 결론:**
- **격리만으로는 부족하다.** 크리덴셜 보호·프롬프트 인젝션 방어·공급망 보안은 격리와 별개로 필요하다.
- **자체 구현은 과소평가되기 쉽다.** Landlock·seccomp·DNS 핀닝을 올바르게 구현하는 데는 전문 보안 공수가 상당히 필요하다.
- **nono는 가장 완성도 높은 포크 베이스지만 Alpha 상태**다(v0.67.1, v1.0 릴리즈 준비 중). OpenSSF Best Practices 인증은 취득했으나 3rd-party 보안 감사는 미완료. 직접 감사를 수행하거나 감사 완료를 기다린 후 투입을 권장한다.

---

## 참고 자료

- NVIDIA OpenShell: github.com/NVIDIA/OpenShell
- nolabs-ai nono: github.com/nolabs-ai/nono
- Anthropic srt: github.com/anthropic-experimental/sandbox-runtime
- Microsoft Agent Governance Toolkit: github.com/microsoft/agent-governance-toolkit
- OWASP Agentic Top 10 (2026): owasp.org/www-project-top-10-for-large-language-model-applications
- CVE-2024-21626 (runc container escape): nvd.nist.gov/vuln/detail/CVE-2024-21626
