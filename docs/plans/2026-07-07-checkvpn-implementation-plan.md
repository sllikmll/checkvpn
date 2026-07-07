# CheckVPN Implementation Plan

> **For Hermes:** implement this plan with strict TDD where practical, keep scope focused on the requested service, and verify on lin with real Docker output.

**Goal:** Build a self-hosted web service that accepts user-provided VPN/proxy configs, runs protocol-specific availability checks, measures latency, stores results, displays them in a web UI/API, packages the app in Docker, deploys it on `lin`, and verifies the running artifact.

**Architecture:** Python FastAPI service with a small SQLite database and a protocol-checker engine. Each config item is stored as a `target`. A background runner executes protocol-specific checkers and writes structured results. The UI shows current status, recent history, latency, and failure reason. For protocols that require a real client runtime (e.g. VLESS, WireGuard, AmneziaWG), the checker uses dedicated subprocess tooling inside the container. For Telegram proxy, the first version focuses on transport-level reachability and protocol-shape validation unless a deeper official client-compatible test path is available during implementation.

**Tech Stack:** Python 3.12+, FastAPI, Jinja2, SQLModel/SQLAlchemy + SQLite, pytest, Docker, xray-core binary, wireguard-tools, curl, jq, iproute2.

---

## Scope decisions

- Support first-class target types:
  - `wireguard`
  - `amneziawg`
  - `vless`
  - `tg-proxy`
- Accept configs as text blobs plus metadata (`name`, `tags`, `server`, optional note).
- Provide:
  - web UI
  - JSON API
  - manual check trigger
  - scheduled checks via app interval
  - result history
- Initial deployment target on `lin`: `/root/docker/checkvpn`, explicit `container_name`, self-contained bind-mounted data directory.
- First deploy uses a direct host port, not reverse-proxy integration.

## Constraints / open items

- Real protocol checks for `wireguard`/`amneziawg` require elevated container capabilities (`NET_ADMIN`, likely `/dev/net/tun`, host modules).
- VLESS real checks require a local Xray client process built from supplied config.
- Telegram proxy “usable” semantics are weaker without a real Telegram session/test client; first version should clearly label this capability.
- Actual configs are provided later by the user, so initial verification uses smoke tests and any safe local/demo cases available.

---

## Task 1: Create repository scaffold

**Objective:** Establish the project structure, metadata, and initial documentation.

**Files:**
- Create: `README.md`
- Create: `.gitignore`
- Create: `pyproject.toml`
- Create: `app/__init__.py`
- Create: `tests/__init__.py`

**Step 1: Write failing test**
- Add a minimal test file asserting the project package imports and app factory exists.

**Step 2: Run test to verify failure**
- Run a targeted pytest command and confirm import failure.

**Step 3: Write minimal implementation**
- Create package skeleton and project metadata.

**Step 4: Run test to verify pass**
- Run the same targeted test.

**Step 5: Commit**
- Commit scaffold files.

---

## Task 2: Define domain models and persistence

**Objective:** Model targets and check results in SQLite.

**Files:**
- Create: `app/models.py`
- Create: `app/db.py`
- Create: `tests/test_models.py`

**Step 1: Write failing tests**
- Test target model validation.
- Test result model serialization.
- Test DB init creates expected tables.

**Step 2: Verify failure**
- Run targeted tests and confirm missing-module/missing-symbol failures.

**Step 3: Implement minimal models**
- Add `Target`, `CheckResult`, protocol enum, status enum.
- Add DB engine/session helpers and `init_db()`.

**Step 4: Verify pass**
- Run targeted tests.

**Step 5: Commit**
- Commit persistence layer.

---

## Task 3: Add config parsers

**Objective:** Parse protocol-specific configs into normalized connection metadata.

**Files:**
- Create: `app/parsers.py`
- Create: `tests/test_parsers.py`

**Step 1: Write failing tests**
- WireGuard parser extracts endpoint/port.
- AmneziaWG parser extracts endpoint/port and AWG markers.
- VLESS URI parser extracts host/port/security/type/sni.
- TG proxy parser extracts host/port/secret from URI or JSON/text payload.

**Step 2: Verify failure**
- Run parser tests.

**Step 3: Implement minimal parsers**
- Support conservative formats first.
- Return normalized dicts and structured parser errors.

**Step 4: Verify pass**
- Run parser tests.

**Step 5: Commit**
- Commit parser layer.

---

## Task 4: Define checker interface and result schema

**Objective:** Create a unified protocol-checker contract.

**Files:**
- Create: `app/checkers/base.py`
- Create: `app/checkers/__init__.py`
- Create: `tests/test_checker_contract.py`

**Step 1: Write failing tests**
- Assert checker output always includes: status, protocol, latency_ms, stage, summary, details.
- Assert unknown protocol fails cleanly.

**Step 2: Verify failure**
- Run contract tests.

**Step 3: Implement minimal interface**
- Add abstract checker class, dataclass/pydantic result model, registry lookup.

**Step 4: Verify pass**
- Run tests.

**Step 5: Commit**
- Commit checker contract.

---

## Task 5: Implement reachability helpers

**Objective:** Build reusable network probes used by protocol checkers.

**Files:**
- Create: `app/netutils.py`
- Create: `tests/test_netutils.py`

**Step 1: Write failing tests**
- TCP probe timeout path.
- URI host extraction.
- Latency timer normalization.

**Step 2: Verify failure**
- Run tests.

**Step 3: Implement minimal helpers**
- TCP connect timing.
- DNS resolution helper.
- Structured subprocess wrapper with timeout.

**Step 4: Verify pass**
- Run tests.

**Step 5: Commit**
- Commit helpers.

---

## Task 6: Implement VLESS checker

**Objective:** Use Xray client mode to validate VLESS configs with a real outbound path.

**Files:**
- Create: `app/checkers/vless.py`
- Create: `tests/test_vless_checker.py`
- Create: `docker/xray/README.md` (or equivalent docs note)

**Step 1: Write failing tests**
- Config generation test for Xray client JSON.
- Failure classification when required VLESS fields are missing.
- Success-path mock test for subprocess result parsing.

**Step 2: Verify failure**
- Run targeted tests.

**Step 3: Implement minimal checker**
- Generate temporary Xray config with local SOCKS inbound and VLESS outbound.
- Start Xray subprocess.
- Probe through SOCKS with curl against a test URL.
- Measure setup latency and HTTP latency.

**Step 4: Verify pass**
- Run targeted tests.

**Step 5: Commit**
- Commit VLESS checker.

---

## Task 7: Implement WireGuard checker

**Objective:** Validate WireGuard configs with a real interface-based tunnel test.

**Files:**
- Create: `app/checkers/wireguard.py`
- Create: `tests/test_wireguard_checker.py`

**Step 1: Write failing tests**
- Interface config generation test.
- Missing endpoint parse failure.
- Result classification from subprocess outputs.

**Step 2: Verify failure**
- Run targeted tests.

**Step 3: Implement minimal checker**
- Build temp wg config.
- Bring up interface in isolated runtime path.
- Detect fresh handshake from `wg show`.
- Run bounded DNS/HTTP probe through the tunnel.
- Always cleanup the interface.

**Step 4: Verify pass**
- Run targeted tests.

**Step 5: Commit**
- Commit WireGuard checker.

---

## Task 8: Implement AmneziaWG checker

**Objective:** Reuse the WireGuard-style flow with AWG-specific config semantics and tool selection.

**Files:**
- Create: `app/checkers/amneziawg.py`
- Create: `tests/test_amneziawg_checker.py`

**Step 1: Write failing tests**
- AWG config detection test.
- AWG parameter preservation test.
- Failure classification test.

**Step 2: Verify failure**
- Run targeted tests.

**Step 3: Implement minimal checker**
- Normalize AWG config.
- Use available AWG-compatible runtime path inside container.
- Detect handshake and perform bounded egress checks.

**Step 4: Verify pass**
- Run targeted tests.

**Step 5: Commit**
- Commit AmneziaWG checker.

---

## Task 9: Implement Telegram proxy checker

**Objective:** Provide a clearly-scoped Telegram proxy availability check.

**Files:**
- Create: `app/checkers/tg_proxy.py`
- Create: `tests/test_tg_proxy_checker.py`

**Step 1: Write failing tests**
- URI parsing normalization.
- Secret format validation.
- TCP/TLS transport reachability result classification.

**Step 2: Verify failure**
- Run tests.

**Step 3: Implement minimal checker**
- Support `tg://proxy` / `tg://socks` / MTProto-style parameter extraction where feasible.
- Perform connect-time measurement.
- Label result semantics explicitly as transport/proxy availability if deep protocol validation is not implemented.

**Step 4: Verify pass**
- Run tests.

**Step 5: Commit**
- Commit Telegram checker.

---

## Task 10: Build application service layer

**Objective:** Add CRUD operations and check execution orchestration.

**Files:**
- Create: `app/services.py`
- Create: `tests/test_services.py`

**Step 1: Write failing tests**
- Create/list target.
- Trigger check persists result.
- Latest result lookup works.

**Step 2: Verify failure**
- Run tests.

**Step 3: Implement minimal service layer**
- CRUD helpers.
- Runner dispatch by protocol.
- Result persistence.

**Step 4: Verify pass**
- Run tests.

**Step 5: Commit**
- Commit service layer.

---

## Task 11: Add FastAPI routes and HTML UI

**Objective:** Expose the service through API and a compact web dashboard.

**Files:**
- Create: `app/main.py`
- Create: `app/templates/index.html`
- Create: `app/static/styles.css`
- Create: `tests/test_api.py`

**Step 1: Write failing tests**
- Health endpoint returns 200.
- Index page renders target list.
- POST target endpoint persists a target.
- Manual run endpoint writes a result.

**Step 2: Verify failure**
- Run API tests.

**Step 3: Implement minimal app**
- FastAPI app factory.
- HTML routes.
- JSON routes.
- Manual trigger route.

**Step 4: Verify pass**
- Run tests.

**Step 5: Commit**
- Commit web layer.

---

## Task 12: Add scheduler

**Objective:** Periodically re-check targets inside the app.

**Files:**
- Create: `app/scheduler.py`
- Create: `tests/test_scheduler.py`

**Step 1: Write failing tests**
- Scheduler selects enabled targets.
- Interval logic skips too-recent checks.

**Step 2: Verify failure**
- Run tests.

**Step 3: Implement minimal scheduler**
- Simple loop/background task.
- Configurable interval.

**Step 4: Verify pass**
- Run tests.

**Step 5: Commit**
- Commit scheduler.

---

## Task 13: Containerize the app

**Objective:** Build a runnable Docker image with required networking tools.

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `docker-compose.yml`
- Create: `entrypoint.sh`
- Create: `tests/test_container_files.py`

**Step 1: Write failing tests**
- Assert Dockerfile exists and references the app entrypoint.
- Assert compose file defines explicit `container_name`.
- Assert health endpoint exists in container config.

**Step 2: Verify failure**
- Run tests.

**Step 3: Implement minimal containerization**
- Base image with Python runtime and protocol tools.
- Volume for app data.
- Host port mapping.
- Required capabilities documented/applied for tunnel checks.

**Step 4: Verify pass**
- Run tests.

**Step 5: Commit**
- Commit container files.

---

## Task 14: Add docs for supported config formats and deployment

**Objective:** Document how the user should provide configs and run the service.

**Files:**
- Expand: `README.md`
- Create: `docs/protocol-notes.md`
- Create: `docs/deploy-lin.md`

**Step 1: Write failing test**
- A simple docs-presence test can assert referenced docs exist.

**Step 2: Verify failure**
- Run doc test.

**Step 3: Implement docs**
- Supported input examples.
- Limits per protocol.
- Docker run / compose instructions.
- Deployment note for `lin`.

**Step 4: Verify pass**
- Run tests.

**Step 5: Commit**
- Commit docs.

---

## Task 15: Build, deploy, and verify on lin

**Objective:** Produce a working artifact and verify it on the target host.

**Files:**
- Use repo root build artifacts and `/root/docker/checkvpn` on `lin`

**Step 1: Build locally or on lin**
- Prefer building on `lin` because local Docker is unavailable.

**Step 2: Validate compose**
- Run `docker compose config` on `lin`.

**Step 3: Start service**
- Run `docker compose up -d --build` in `/root/docker/checkvpn`.

**Step 4: Verify runtime**
- `docker compose ps`
- `docker logs --tail 100 checkvpn`
- `curl http://127.0.0.1:<port>/health`
- `curl http://127.0.0.1:<port>/`

**Step 5: Add real configs when user provides them**
- Import configs.
- Trigger checks.
- Verify UI/history/result semantics.

**Step 6: Commit and push**
- Push final code and docs to `checkvpn`.

---

## Verification checklist

- [ ] Repo contains source, tests, docs, Docker files.
- [ ] `pytest` passes.
- [ ] Docker image builds on `lin`.
- [ ] Container starts on `lin`.
- [ ] `/health` returns 200.
- [ ] UI loads.
- [ ] At least smoke-level checks can run without crashing.
- [ ] Result format clearly states what each protocol check proves.
- [ ] Code pushed to GitHub repo `checkvpn`.

## Initial deployment defaults

- App host port on `lin`: `8098`
- Compose directory on `lin`: `/root/docker/checkvpn`
- Container name: `checkvpn`
- Data dir: `/root/docker/checkvpn/data`

## Notes on official sources to consult during implementation

- WireGuard protocol/site docs.
- Xray/VLESS docs for config semantics.
- AmneziaWG upstream repo/docs.
- Telegram MTProto transport docs.
- Docker / Linux networking behavior for privileged tunnel checks.
