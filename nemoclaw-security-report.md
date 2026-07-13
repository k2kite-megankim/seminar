<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# NemoClaw 보안 아키텍처 보고서

**작성일:** 2026-07-01
**버전:** NemoClaw 현행 main 브랜치 기준

---

## 개요

NemoClaw는 OpenClaw, Hermes 등의 AI 에이전트를 NVIDIA OpenShell 샌드박스 안에서 안전하게 운영하기 위한 참조 스택이다. 에이전트는 인터넷, AI 제공자 API, 메시지 플랫폼 등 외부 시스템에 지속적으로 접근하며, 이 과정에서 자격증명 유출, 내부망 침투, 권한 상승, 공급망 공격 등 다양한 위협이 발생할 수 있다.

NemoClaw는 이를 막기 위해 **5개의 독립 보안 레이어**를 중첩 적용한다. 각 레이어는 서로 다른 공격 벡터를 담당하며, 하나가 우회되더라도 다음 레이어에서 막힌다는 Defense in Depth 원칙을 따른다.

이 보고서는 NemoClaw의 보안 기능을 계층별로 분석한다.

---

## 1. 버전 및 컴포넌트 구성

### 1.1 버전 정보

| 컴포넌트 | 버전 | 비고 |
|---------|------|------|
| **NemoClaw CLI** | `0.1.0` | main 브랜치, 커밋 `c6113be` |
| **NemoClaw Plugin** | `0.1.0` | OpenClaw Commander 확장 |
| **Blueprint** | `0.1.0` | 샌드박스 오케스트레이션 정의 |
| **OpenShell** | `0.0.44` (고정) | min/max 동일 — 정확히 이 버전 필요 |
| **OpenClaw** | `≥ 2026.3.11` | 최소 버전 요구 |
| **Sandbox 이미지** | `sha256:b3d832b5...` | SHA256 다이제스트 핀닝 |
| **Node.js** | `≥ 22.16.0` | CLI·플러그인 공통 엔진 요구사항 |
| **TypeScript** | `^6.0.2` | ES2022 타겟 컴파일 |
| **Vitest** | `^4.1.0` | 테스트 프레임워크 |

OpenShell 버전이 `min = max = 0.0.44`로 고정되어 있다는 점이 중요하다. 다른 버전의 OpenShell과는 호환되지 않으며, OpenShell 업그레이드 시 NemoClaw도 함께 업데이트해야 한다.

---

## 2. 보안 아키텍처 전체 구조

```
┌──────────────────────────────────────────────────────────────────┐
│                         외부 인터넷                               │
└───────────────────────────┬──────────────────────────────────────┘
                            │  "approved only"
┌───────────────────────────▼──────────────────────────────────────┐
│  OpenShell Gateway                                               │
│  ├─ [Layer 1] 네트워크 정책 — egress 화이트리스트 + L7 검사       │
│  ├─ [Layer 4] 게이트웨이 인증 — device pairing                   │
│  └─ [Layer 5] 추론 라우팅 — inference.local 크리덴셜 격리         │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│  Sandbox (Docker 컨테이너, OpenShell 관리)                        │
│  ├─ [Layer 2] 파일시스템 — Landlock LSM + read-only 마운트        │
│  └─ [Layer 3] 프로세스 — capabilities drop + ulimit + non-root   │
│                                                                  │
│  Plugin Layer (OpenClaw NemoClaw plugin)                         │
│  ├─ CLI 출력 시크릿 리댁션 (3모드)                                │
│  └─ 메모리 파일 시크릿 스캐너 (before_tool_call 훅)               │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 격리(Isolation) vs 에이전트 보안(Agent Security)

NemoClaw의 5개 레이어는 성격이 다른 두 가지 보안 목적을 동시에 달성한다.

| 구분 | 정의 | 비교 대상 |
|------|------|---------|
| **격리 (Isolation)** | 컨테이너를 외부로부터 분리 — 프로세스 탈출, 커널 접근 차단 | Docker, Firecracker, gVisor도 제공 |
| **에이전트 보안 (Agent Security)** | AI의 행동 자체를 제어 — 크리덴셜 유출, 프롬프트 인젝션, 승인되지 않은 LLM 접근 차단 | NemoClaw · nono만 제공 |

> **핵심:** Firecracker나 gVisor로 격리를 완벽히 해도, AI 에이전트가 허용된 네트워크 요청에 API 키를 실어 외부로 전송하는 것은 격리 기술로 막을 수 없다. 크리덴셜 보호와 행동 제어는 별도의 레이어가 필요하다.

**레이어별 분류:**

| 레이어 | 격리 ✓ | 에이전트 보안 ✓ | 성격 |
|--------|--------|---------------|------|
| **1. 네트워크** | deny-by-default, 허용목록 | 바이너리 스코프, L7 검사, DNS 핀닝 | 혼합 |
| **2. 파일시스템** | Landlock, read-only 마운트 | **Shields Up** (설정 변조 방어) | 혼합 |
| **3. 프로세스** | capabilities drop, NNP, ulimit | — | 격리 전용 |
| **4. 크리덴셜** | — | 3모드 리댁션, 메모리 스캐너, inference.local 분리 | 에이전트 보안 전용 |
| **5. 추론 격리** | — | inference.local 게이트웨이 | 에이전트 보안 전용 |

레이어 3(프로세스)은 순수 격리 레이어로, Docker나 일반 컨테이너 보안과 겹친다. 레이어 4·5와 레이어 1·2의 에이전트 보안 기능은 NemoClaw가 독자적으로 설계한 부분이다.

---

## 3. Layer 1 — 네트워크 보안

> **레이어 성격:** 격리 + 에이전트 보안 혼합
> - 3.1 deny-by-default, 3.5 정책 티어 → **격리** (일반 방화벽과 유사)
> - 3.2 바이너리 스코프, 3.3 L7 검사, 3.4 DNS 핀닝 → **에이전트 보안** (NemoClaw 독자 설계)

### 3.1 Deny-by-Default Egress `[격리]`

샌드박스는 모든 아웃바운드 연결을 기본 차단한다. `nemoclaw-blueprint/policies/` 아래의 YAML 정책 파일에 명시된 엔드포인트만 허용된다. 에이전트가 미허가 엔드포인트에 접근하면 OpenShell이 차단 후 운영자에게 TUI 승인 요청을 보낸다.

### 3.2 바이너리 스코프 엔드포인트 제어 `[에이전트 보안]`

NemoClaw의 가장 독특한 설계다. 단순히 호스트/포트를 허용하는 것이 아니라 **어떤 실행 파일이 연결을 시도하는지**를 함께 검사한다.

```yaml
# nemoclaw-blueprint/policies/presets/github.yaml
network_policies:
  github:
    endpoints:
      - host: github.com
        port: 443
        access: full
      - host: api.github.com
        port: 443
        access: full
    binaries:
      - { path: /usr/bin/git }   # /usr/bin/git 만 접근 가능
```

OpenShell은 `/proc/<pid>/exe`(커널이 신뢰하는 실행 파일 경로, `argv[0]`이 아님)를 읽고 최초 사용 시 SHA256 해시를 계산한다. 런타임에 바이너리가 교체되면 해시 불일치로 즉시 차단된다. `curl`이나 Python 스크립트로 허용된 도메인에 데이터를 유출하려 해도, 해당 바이너리가 목록에 없으면 차단된다.


### 3.3 L7 HTTP 검사 `[에이전트 보안]`

`protocol: rest`를 설정하면 OpenShell 게이트웨이가 TLS를 종료하고 개별 HTTP 요청의 메서드/경로를 검사한다.

```yaml
- host: integrate.api.nvidia.com
  port: 443
  protocol: rest
  rules:
    - method: POST
      path: /v1/chat/completions
    - method: GET
      path: /v1/models
```

`protocol` 필드가 없으면 L4 pass-through로 동작하며, 호스트/포트/바이너리만 확인 후 TCP 스트림을 그대로 통과시킨다. REST API에는 `protocol: rest`와 명시적 규칙을 적용하는 것이 권장된다.


### 3.4 SSRF 방어 및 DNS 핀닝 `[에이전트 보안]`

**핵심 파일:** `nemoclaw/src/blueprint/ssrf.ts`

SSRF(Server-Side Request Forgery) 공격을 4단계로 방어한다.

```typescript
// 1단계: URL 스킴 화이트리스트 (http/https만 허용)
const ALLOWED_SCHEMES = new Set(["https:", "http:"]);

// 2단계: 호스트명 수준 private 주소 차단
if (isPrivateHostname(hostname)) {
  throw new Error("Connections to internal networks are not allowed.");
}

// 3단계: DNS 해석 후 모든 resolved IP가 public인지 검증
for (const { address } of addresses) {
  if (isPrivateIp(address)) {
    throw new Error(`Resolves to private address ${address}.`);
  }
}

// 4단계: DNS 핀닝 — 검증된 IP로 호스트명 교체 (TOCTOU 방어)
pinned.hostname = first.family === 6 ? `[${first.address}]` : first.address;
return { url, pinnedUrl: pinned.toString() };  // 실제 연결은 pinnedUrl 사용
```

특히 **DNS 핀닝**이 핵심이다. 검증 시점에 공개 IP를 반환했다가 연결 시점에 내부망 IP를 반환하는 DNS rebinding TOCTOU 공격을 원천 차단한다.


### 3.5 정책 티어 시스템 `[격리]`

`nemoclaw-blueprint/policies/tiers.yaml`에 정의된 3단계 기본 포스처:

| 티어 | 설명 | 포함 프리셋 |
|------|------|------------|
| `restricted` | 기본값. 서드파티 네트워크 접근 없음 | (없음) |
| `balanced` | 개발 도구, 웹 검색, 패키지 레지스트리 | npm, pypi, huggingface, brew, brave |
| `open` | 메시징 플랫폼 포함 전체 접근 (사용자 책임) | balanced + slack, discord, telegram, jira 등 |

---

## 4. Layer 2 — 파일시스템 보안

> **레이어 성격:** 격리 + 에이전트 보안 혼합
> - 4.1 Landlock, 4.2 read-only 마운트, 4.4 TOCTOU 방지 → **격리** (일반 컨테이너 보안과 유사)
> - 4.3 Shields Up → **에이전트 보안** (프롬프트 인젝션 → 설정 변조 방어, NemoClaw 독자 설계)

### 4.1 Landlock LSM `[격리]`

Linux Security Module인 Landlock(커널 5.13+)이 커널 레벨에서 파일시스템 접근 규칙을 강제한다.

**적용 흐름:**

```
컨테이너 시작
  → nemoclaw-start 엔트리포인트 실행
    → OpenClaw 프로세스 시작 전에 landlock_restrict_self() 호출
      → 이 시점부터 OpenClaw는 허용된 경로 외 파일시스템 접근 불가 (비가역)
        → OpenClaw가 spawn하는 모든 자식 프로세스도 동일 제한 상속
```

Landlock은 **프로세스가 스스로 자신을 제한**하는 방식이라 root 권한이 필요 없다. `landlock_restrict_self()` 호출 이후에는 프로세스가 스스로 제한을 해제할 수 없다.

현재 `compatibility: best_effort`로 설정되어 있어 커널이 지원하지 않으면 무음으로 건너뛰고 DAC(파일 소유권/권한)만으로 동작한다. 프로덕션 환경에서는 커널 5.13 이상이 권장된다.

### 4.2 마운트 기반 읽기 전용 시스템 경로 `[격리]`

컨테이너 마운트를 통해 시스템 디렉토리를 읽기 전용으로 고정한다.

| 경로 | 접근 | 보호 목적 |
|------|------|----------|
| `/usr`, `/lib`, `/bin` | 읽기 전용 | 시스템 바이너리 변조 방지 |
| `/etc` | 읽기 전용 | DNS 설정, TLS 신뢰 저장소 변조 방지 |
| `/proc`, `/dev/urandom` | 읽기 전용 | 커널 인터페이스 접근 제한 |
| `/sandbox`, `/tmp` | 읽기-쓰기 | 에이전트 워크스페이스 |

### 4.3 에이전트 설정 디렉토리 잠금 — Shields Up `[에이전트 보안]`

`/sandbox/.openclaw`는 기본적으로 에이전트가 쓸 수 있는 상태(`2770 sandbox:sandbox`)로 시작한다. 민감한 워크로드에서는 `shields up` 명령으로 세 단계 잠금을 적용한다.

**shields up의 목적:** AI 에이전트는 프롬프트 인젝션 공격을 받으면 자기 설정을 변경하도록 유도될 수 있다. "네트워크 정책을 풀어라", "다른 모델로 전환해라" 같은 지시를 따르는 것이다. shields up은 에이전트 자신도 `/sandbox/.openclaw` 설정을 수정하지 못하게 잠가서 이런 공격을 원천 차단한다.

**Step 1 — 권한 변경**
```
/sandbox/.openclaw/   → 755  root:root   (에이전트 쓰기 불가)
openclaw.json         → 444  root:root   (읽기 전용)
```

**Step 2 — chattr +i (immutable bit)**

Linux 파일시스템 레벨에서 불변 플래그를 설정한다. root도 이 플래그를 먼저 제거하지 않으면 쓸 수 없어 `chmod → 쓰기 → chmod 원복` 우회를 차단한다.

**Step 3 — SHA256 봉인**

잠금 시점의 `sha256sum(openclaw.json)`을 기록한다. 이후 검증 시 권한·소유자·immutable bit 외에 콘텐츠 해시까지 비교하므로, root가 변조 후 권한을 원복해도 해시 불일치로 감지된다.

### 4.4 심볼릭 링크 및 TOCTOU 공격 방지 `[격리]`

Dockerfile 패치 및 설정 파일 쓰기 시 `O_NOFOLLOW` 플래그와 atomic rename 패턴을 사용한다.

```typescript
// credential-filter.ts
fd = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW); // 심볼릭 링크 추적 거부
writeFileSync(tmpPath, contents, { mode: 0o600 });
renameSync(tmpPath, filePath); // 원자적 교체
```

Dockerfile 패치 코드도 동일하게 시작 전 심볼릭 링크 여부를 검사하고, 읽기와 쓰기 사이에 링크로 교체되는 TOCTOU 공격도 별도 테스트로 커버한다(`dockerfile-patch-security.test.ts`).


---

## 5. Layer 3 — 프로세스 보안

> **레이어 성격:** 격리 전용
> 프로세스 권한을 최소화하는 일반 컨테이너 보안 강화 기법. Docker·K8s 보안 가이드와 유사하며 AI 에이전트 특화 기능은 없다. 격리 레이어 중 다른 보안 솔루션과 가장 겹치는 부분이다.

### 5.1 Linux Capability 드롭 `[격리]`

엔트리포인트(`capsh`)에서 시작 시 위험 capability를 제거하고, `setpriv`로 사용자 전환 시 추가 제거한다.

**capsh 단계 제거 (10개):**

| Capability | 제거 이유 |
|---|---|
| `CAP_SYS_ADMIN` | 가장 강력한 권한. 마운트, 네임스페이스 조작, 컨테이너 탈출 가능 |
| `CAP_SYS_PTRACE` | 다른 프로세스 메모리 읽기/쓰기. 타 프로세스 크리덴셜 탈취 가능 |
| `CAP_NET_RAW` | raw 소켓 생성. 네트워크 패킷 스니핑, ARP 스푸핑 가능 |
| `CAP_DAC_OVERRIDE` | 파일 권한 무시. shields up의 `444 root:root` 잠금 우회 가능 |
| `CAP_SYS_CHROOT` | 루트 디렉토리 변경. 파일시스템 격리 탈출 가능 |
| `CAP_FSETID` | setuid/setgid 비트 유지. 권한 상승 바이너리 생성 가능 |
| `CAP_SETFCAP` | 파일에 capability 부여. 임의 바이너리에 권한 심기 가능 |
| `CAP_MKNOD` | 장치 파일 생성. `/dev/mem` 등으로 커널 메모리 접근 가능 |
| `CAP_AUDIT_WRITE` | 커널 감사 로그 조작. 침입 흔적 삭제 가능 |
| `CAP_NET_BIND_SERVICE` | 1024 이하 포트 열기. 80/443 포트 하이재킹 가능 |

**setpriv 단계 추가 제거:**
`CAP_SETUID`, `CAP_SETGID`, `CAP_FOWNER`, `CAP_CHOWN`, `CAP_KILL`

기본값은 best-effort이며, 고위험 환경에서는 `NEMOCLAW_REQUIRE_CAP_DROP=1`로 fail-closed 전환이 가능하다.

Docker Compose 레벨에서도 중첩 적용을 권장한다:

```yaml
services:
  nemoclaw-sandbox:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    ulimits:
      nproc:
        soft: 512
        hard: 512
      nofile:
        soft: 65536
        hard: 65536
```

### 5.2 게이트웨이 프로세스 격리

에이전트(`sandbox` 사용자)와 게이트웨이(`gateway` 사용자)를 별도 사용자로 분리한다. 에이전트가 게이트웨이 프로세스를 kill하고 변조된 설정으로 재시작하는 "fake-HOME 공격"을 차단한다.

### 5.3 No-New-Privileges

OpenShell이 샌드박스 내부에서 `PR_SET_NO_NEW_PRIVS`를 `prctl()`로 설정한다. 이 설정은 비가역적이며, 해당 프로세스와 모든 자식 프로세스가 영구적으로 새 권한을 얻을 수 없게 된다. setuid 바이너리를 실행해도 root 권한으로 상승되지 않아 컨테이너 내 루트 탈취를 막는다.

### 5.4 리소스 제한

```bash
ulimit -u 512    # fork bomb 방지 (프로세스 수 상한)
ulimit -n 65536  # FD 고갈 방지 (파일 디스크립터 상한)
```

### 5.5 빌드 툴체인 제거

Dockerfile에서 명시적으로 제거:

| 제거 대상 | 이유 |
|----------|------|
| `gcc`, `g++`, `make` | 커널 익스플로잇 및 악성 바이너리 컴파일 불가 |
| `netcat-openbsd`, `ncat` | HTTP 정책을 우회하는 원시 TCP 연결 불가 |

### 5.6 PATH 하드닝

엔트리포인트가 시작 시 `PATH`를 시스템 디렉토리로 고정한다. 에이전트가 쓰기 가능한 디렉토리에 악성 `curl`이나 `git`을 만들어 명령 탈취를 시도하는 것을 막는다.


---

## 6. Layer 4 — 크리덴셜 보호

> **레이어 성격:** 에이전트 보안 전용
> AI가 API 키를 탈취·유출하는 것을 막는 NemoClaw 독자 설계. 일반 컨테이너·방화벽 보안에는 없는 레이어이며, AI 에이전트를 운영하는 환경에서만 의미가 있다.

NemoClaw의 크리덴셜 보호 시스템은 네 개의 서브시스템으로 구성된다.

### 6.1 시크릿 패턴 정의 (단일 진실 공급원)

`src/lib/security/secret-patterns.ts`가 20개 이상 토큰 형식의 정규식을 정의하며, 모든 TypeScript 소비자가 이 파일을 임포트한다.

```typescript
export const TOKEN_PREFIX_PATTERNS: RegExp[] = [
  /nvapi-[A-Za-z0-9_-]{10,}/g,          // NVIDIA API key
  /sk-proj-[A-Za-z0-9_-]{10,}/g,        // OpenAI (sk-ant- 전에 매칭)
  /sk-ant-[A-Za-z0-9_-]{10,}/g,         // Anthropic
  /(?:xox[bpas]|xapp)-[A-Za-z0-9-]{10,}/g, // Slack (5종 통합)
  /A(?:K|S)IA[A-Z0-9]{16}/g,            // AWS (AKIA=장기, ASIA=임시)
  /ghp_[A-Za-z0-9_-]{10,}/g,            // GitHub
  // ... 총 16개 prefix 패턴 + context-anchored 패턴
];
```

### 6.2 3단계 리댁션 (redact.ts)

용도에 따라 세 가지 리댁션 모드를 제공한다.

| 함수 | 동작 | 사용처 |
|------|------|--------|
| `redact()` | 앞 4자 보존 후 마스킹 | CLI 출력 (runner.ts) |
| `redactFull()` | 완전 치환 (`<REDACTED>`) | 진단 덤프 (debug.ts) |
| `redactSensitiveText()` | 완전 치환 + 240자 잘라냄 | 온보딩 세션 로그 |

URL도 별도 처리하여 Basic Auth 자격증명과 토큰 쿼리 파라미터를 마스킹한다. `redactForLog()`는 임의의 JSON 객체를 순환 참조 안전하게 순회하며 민감 키 값을 자동으로 치환한다.

### 6.3 설정 파일 크리덴셜 스트리핑 (credential-filter.ts)

백업 및 마이그레이션 시 크리덴셜이 파일시스템에 저장되지 않도록 4중 탐지 후 플레이스홀더(`[STRIPPED_BY_MIGRATION]`)로 교체한다.

```typescript
// 탐지 기법 1: 명시적 필드명 세트
const CREDENTIAL_FIELDS = new Set(["apiKey", "api_key", "token", "secret", "password"]);

// 탐지 기법 2: camelCase 접미사 패턴
const CREDENTIAL_FIELD_PATTERN = /(?:access|refresh|client|...)(?:Token|Key|Secret|Password)$/;

// 탐지 기법 3: SCREAMING_SNAKE_CASE (MCP 서버 env 블록)
const ENV_SECRET_FIELD_PATTERN = /^(?:[A-Z0-9]+_)*(?:TOKEN|KEY|SECRET|PASSWORD|...)S?$/;

// 탐지 기법 4: HTTP 헤더명
const CREDENTIAL_HEADER_NAMES = new Set(["authorization", "proxy-authorization", "cookie"]);
```

### 6.4 메모리 시크릿 스캐너 (secret-scanner.ts)

OpenClaw 플러그인이 `before_tool_call` 훅으로 Write/Edit 도구 호출을 가로채 메모리 경로에 시크릿이 기록되는 것을 방지한다.

**isMemoryPath() — 3가지 경로 분류기:**

```typescript
// 분류기 1: 절대 경로 세그먼트
const MEMORY_PATH_SEGMENTS = [
  "/.openclaw/memory/", "/.openclaw/workspace/",
  "/.openclaw/credentials/", "/.nemoclaw/", ...  // 14개
];

// 분류기 2: 캐노니컬 워크스페이스 파일명 (경로 무관)
const MEMORY_BASENAMES = new Set([
  "IDENTITY.md", "MEMORY.md", "SOUL.md", "USER.md", "AGENTS.md"
]);

// 분류기 3: 상대 경로 프리픽스
const MEMORY_RELATIVE_PREFIXES = [".openclaw/", ".nemoclaw/", "memory/"];
```

경로 정규화 로직이 `../` 트래버설 공격도 방어한다. `safeResolvePath()`는 OpenClaw 임베디드 폴백 런타임에서 `api.resolvePath`가 `undefined`를 반환하는 경우에도 TypeError 없이 원본 경로로 폴백한다.


---

## 7. Layer 5 — 추론(Inference) 크리덴셜 격리

> **레이어 성격:** 에이전트 보안 전용
> AI가 승인되지 않은 LLM에 연결하거나 API 키를 직접 소유하는 것을 막는 NemoClaw 독자 설계. 이 레이어는 AI 에이전트가 존재하기 때문에 필요한 레이어로, 일반 보안 솔루션에는 대응 개념이 없다.

에이전트는 절대 AI 제공자 API 키를 직접 소유하지 않는다:

```
에이전트 → inference.local → OpenShell 게이트웨이 → api.nvidia.com
                                     ↑
                           여기서만 실제 API 키 보유
```

이 아키텍처는 설정으로 변경할 수 없다. 네트워크 정책에 `api.openai.com`이나 `api.anthropic.com`을 직접 추가하면 이 격리가 우회되며, 문서에서 명시적으로 경고하는 흔한 실수다. `claude-code` 프리셋은 NemoClaw 추론 라우팅이 아닌 별도의 Claude Code CLI 실행을 위한 예외적 용도다.

---

## 8. 공급망 보안

### 8.1 이미지 다이제스트 핀닝

`nemoclaw-blueprint/blueprint.yaml`에서 샌드박스 이미지를 불변 SHA256 다이제스트로 참조한다:

```yaml
image: "ghcr.io/nvidia/openshell-community/sandboxes/openclaw@sha256:b3d832b5..."
digest: "sha256:b3d832b5..."  # 최상위 필드로 이중 검증
```

CI 회귀 테스트가 mutable 태그(`:latest`) 참조를 병합 전 자동 차단한다. 레지스트리 침해나 실수로 인한 `:latest` 교체를 막는다.


---

## 9. 감사 로그 범위

NemoClaw의 로그는 단일 위치에 있지 않다. 레이어별로 발생한 보안 이벤트가 각각 다른 저장소에 기록되며, 모두 **append-only** 구조로 에이전트가 변조·삭제할 수 없다.

### 9.1 기록되는 것

| 이벤트 유형 | 기록 내용 | 저장 위치 | 무결성 |
|------------|----------|----------|--------|
| **Shields 상태 변경** | shields up/down/auto-restore/failed 이벤트, config 변경(inference-set, config-set), 봉인 시점 SHA256 | `~/.nemoclaw/state/shields-audit.jsonl` | append-only + `chattr +i` |
| **설정 파일 무결성** | 보호 파일의 SHA256 상태 (권한·소유자·hash) | shields audit에 포함 | 위와 동일 |
| **메모리 경로 Write/Edit 시도** | 도구명, 대상 경로, 차단 여부 | before_tool_call 훅 → plugin 로그 | OpenClaw 플러그인 로그 |
| **네트워크 요청** | 도메인, HTTP method/path (L7 REST 엔드포인트) | OpenShell 게이트웨이 로그 | OpenShell 관리 |
| **바이너리 스코프 위반** | 차단된 프로세스의 `/proc/<pid>/exe` 경로, 대상 도메인 | OpenShell 게이트웨이 로그 | OpenShell 관리 |
| **크리덴셜 스트리핑** | 탐지된 필드명, 치환 여부 (값 제외) | 마이그레이션 로그 | — |
| **게이트웨이 인증 거부** | 거부된 pair 시도, clientId, 스코프 | OpenShell 게이트웨이 로그 | OpenShell 관리 |

### 9.2 기록되지 않는 것

| 항목 | 이유 |
|------|------|
| **크리덴셜 실제 값** | 모든 로그 경로에서 redact()/redactFull() 통과 후 기록 — 키 이름만 남음 |
| **파일 내용** | 경로와 이벤트 유형만 기록 |
| **HTTP 요청/응답 바디** | L7 검사는 method/path만 — 페이로드 내용은 기록 안 함 |
| **syscall 전체 스트림** | before_tool_call은 도구 호출 레벨 인터셉트. nono처럼 커널 syscall을 전수 기록하지는 않음 |
| **에이전트 stdout/stderr** | 도구 호출만 인터셉트, 에이전트 일반 출력은 로그 대상 아님 |

### 9.3 로그 무결성 보장 구조

```
shields-audit.jsonl
  ├─ append-only (O_APPEND 플래그)
  └─ chattr +i (immutable bit) → root도 삭제·수정 불가, 에이전트는 당연히 불가

OpenShell 게이트웨이 로그
  └─ 컨테이너 외부 (호스트 또는 원격 컬렉터) → 에이전트 접근 범위 밖
```

에이전트가 **자신의 활동 기록을 지울 수 없다**는 것이 핵심이다. `CAP_AUDIT_WRITE`를 제거(5.1)했으므로 커널 감사 로그도 조작 불가.

### 9.4 nono·srt와의 비교

| 항목 | NemoClaw | nono | srt |
|------|:--------:|:----:|:---:|
| **도구 호출 레벨 로그** | ✓ before_tool_call | 불명 (감사 원장 범위 미확인) | ✗ |
| **네트워크 요청 로그** | ✓ L7 method/path | △ 프록시 경유 증명만 | ✓ L7 MITM |
| **syscall 스트림 로그** | ✗ | ✓ seccomp-notify | △ 위반만 |
| **로그 무결성** | ✓ chattr+i | ✓ Merkle tree | ✗ |
| **크리덴셜 값 로그 제외** | ✓ redact() 강제 | ✓ | △ 콜백 구현에 의존 |

> nono의 감사 원장이 도구 호출 수준인지 syscall 수준인지는 소스 확인 필요. syscall 수준이라면 nono가 더 넓은 커버리지를 갖는다.

---

## 참고 자료

- NemoClaw 소스: `/docs/security/best-practices.mdx`, `/docs/deployment/sandbox-hardening.mdx`
- NemoClaw 핵심 보안 코드: `src/lib/security/`, `nemoclaw/src/blueprint/ssrf.ts`, `nemoclaw/src/security/`
- OpenShell Security Best Practices: `https://docs.nvidia.com/openshell/latest/security/best-practices.html`
