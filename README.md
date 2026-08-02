# pki-executor

A VM-resident agent that mediates post-boot control of a deployed VM on behalf
of [EC-PKI-Playground](https://github.com/Arnesh-EC/EC-PKI-Playground).

## Vision

`configgen` generates this agent's first-boot configuration, `isokit` packs it
into the VM's boot ISO, and `vmkit` deploys the VM. Once the VM boots, the
executor runs as a persistent Windows Service, phones home to the
EC-PKI-Playground backend to establish two-way communication, and then
executes a **role-differentiated command surface**: guests get a narrow,
allowlisted set of commands; operators get the broad/arbitrary set, gated by
the backend's already-reserved `Capability.VM_EXEC_ARBITRARY`
(`backend/src/app/core/authz.py`). The end goal is to compose an entire PKI
topology on the EC-PKI-Playground dashboard, hit deploy, and have this agent
carry out the build (AD DS forest promotion, ADCS install, CDP/AIA
configuration, domain join, cert enrollment — see
`pki-lab-guides/vm-building.md` for the manual reference process) behind the
scenes, streaming progress back to the frontend.

Windows Server is the only target for now; Linux support is a stated future
goal.

## Out of scope for v0 / v1

v0 proved the core architecture — role-gated command dispatch, PowerShell
execution, Windows Service lifecycle — with a small, real, testable slice
and no networking at all. v1 (this revision) wires up the actual phone-home
mechanism: the executor connects out to the backend, receives dispatched
commands, and streams their progress back — see "Phone-home" below. Still
deliberately **not** included:

- **Automatic, ISO-embedded registration.** The backend-issued `vm_id`/
  `agent_token` pair (see below) is copied into `executor.toml` by a
  human today, standing in for what a real deployment will do automatically
  once the `isokit`/`configgen` gaps below close.
- The full ADCS command catalog from `vm-building.md` (AD DS forest
  promotion, CA install, template publishing, OCSP configuration, etc.) —
  the implemented set is the 3 v0 commands chosen to exercise every point on
  the role spectrum, plus the hostname/IP read-write parity set (see below).
- Packaging/deployment integration with `configgen`/`isokit`/`vmkit`.

## Future integration points

Gaps identified in the sibling repos while designing this one, so they don't
need rediscovering later:

- **isokit** (`build_script_iso`) only accepts text scripts, force-decoded as
  UTF-8 with rewritten line endings — it cannot embed a compiled binary today.
  Shipping this executor's binary via the boot ISO will need a new
  binary-embedding API there.
- **vmkit** has no guest-level communication (no VMware Tools/VIX guest-exec,
  no IP/hostname readback) — there is no existing way for the backend to
  correlate an inbound "phone home" call to a specific VM record. `vm_id` +
  `agent_token` (see "Phone-home" below) are the correlation mechanism that
  will eventually be baked into the config ISO automatically; today they're
  copied in by hand.
- **configgen** has no plugin/extension point for emitting an "install the
  executor" first-boot step — only hostname/network/local-password
  renderers exist today.

## Phone-home

`connect` (and, on Windows, `service run`) opens a long-lived WebSocket to
`{backend.url}/api/executor/connect?vm_id=&token=` and stays connected,
reconnecting with capped backoff on any drop. Each inbound frame is a
dispatched command tagged with a job id and the role the backend
authenticated the calling human as:

```json
{"job_id": "...", "command": "cert.verify", "params": {"path": "..."}, "role": "guest"}
```

The **backend is the authoritative capability gate** — it checks the human's
role via its own `require_capability` before ever forwarding a command, and
that forwarded `role` is what `CommandRegistry::dispatch` checks here, not
`identity.role` from local config (which is only a fallback for the one-shot
`run` CLI path, which has no backend in the loop). This local dispatch check
is a second, structural gate, not the primary one.

Progress streams back as `{"job_id": "...", "state": <OpRunState>}` frames,
which the backend relays onto the existing `/api/ws/jobs/{job_id}` transport
— no new frontend plumbing needed to watch it.

Get a `vm_id`/`agent_token` pair via `POST /api/executor/register` on the
backend before running `connect`; see the backend's own docs for the request
shape.

## Command surface

| Command | Capability | Guest-eligible? | Source |
|---|---|---|---|
| `hostname.rename` | `VmUpdate` | No | `Rename-Computer` pattern, used repeatedly across `vm-building.md` |
| `hostname.read` | `VmRead` | **Yes** | `[System.Net.Dns]::GetHostName()` — read half of the rename command |
| `ip.read` | `VmRead` | **Yes** | `Get-NetIPAddress`, non-loopback IPv4 enumeration |
| `ip.write` | `VmUpdate` | No | Static IPv4 assignment (`Set-NetIPInterface -Dhcp Disabled` + `New-NetIPAddress`), the guide's first-boot pattern |
| `cert.verify` | `VmRead` | **Yes** | `certutil -verify -urlfetch`, the guide's own health-check command |
| `powershell.exec_arbitrary` | `VmExecArbitrary` | **No** (by construction) | Reserved escape hatch — must never reach a guest |

`hostname.read`/`ip.read`/`ip.write` are the read-write parity set every
template machine will eventually need (deployed manually today; per-template
auto-provisioning is a later phase).

`cert.verify` is deliberately guest-eligible to prove the *allowed* path
through the registry, not just the forbidden one. `powershell.exec_arbitrary`
is the load-bearing negative case: `CommandRegistry::dispatch` must reject it
for `Role::Guest` before the handler ever runs.

### The rest of the catalog

The table above is the v0 pattern set, not the full surface. The two-tier ADCS
lab of `pki-lab-guides/vm-building.md` (DC01/CA01/CA02/SRV1/WIN11) is covered
end to end today — forest promotion, both CA tiers, CDP/AIA, template
publication, IIS CertEnroll, domain join, and the Online Responder including
`ocsp.configure_revocation`, which drives `CertAdm.OCSPAdmin` from PowerShell
rather than the `windows-rs` executor once thought necessary. `commands/mod.rs`
registers every handler and is the authoritative list.

## Architecture

- `authz.rs` — local mirror of the backend's `Role`/`Capability`/
  `ROLE_CAPABILITIES`. Wire values must match `authz.py`'s `.value` strings
  exactly; there is no automated sync between the two languages.
- `report.rs` — `OpRunState`/`OpStatus` mirror the backend's
  `app/core/jobs/models.py::OpRunState` shape, so a future backend adapter is
  a serializer, not a redesign.
- `registry.rs` — `CommandRegistry::dispatch` checks the caller's role against
  a handler's required capability *before* calling into it — structurally
  impossible for a new handler to forget its own gate.
- `powershell.rs` — `PowerShellExecutor` trait, with a real
  `std::process::Command`-based implementation and a mock for tests. Shells
  out rather than binding COM, since every v0 command has a plain PowerShell
  equivalent and this is what's testable from a non-Windows dev machine.
- `commands/` — the command handlers.
- `phonehome.rs` — the WebSocket client: connects, dispatches inbound
  commands via `spawn_blocking` (dispatch/PowerShell execution are
  synchronous and must not block the async reactor), streams `OpRunState`
  progress back, reconnects with capped backoff. `handle_command` (the
  framing/dispatch translation) is a plain sync function, unit-tested with
  an in-memory channel standing in for the socket.
- `cli.rs` — `run` (one-shot local dispatch, no backend), `connect` (phone
  home and serve commands, any OS), `service` (Windows SCM integration).
- `service/` — `console.rs::run_loop` bridges the sync CLI/SCM entry points
  to the async `phonehome::run_forever` with a dedicated Tokio runtime, and
  is shared by both the `connect` path and the real SCM-invoked path — one
  control-flow implementation, not two. `scm.rs` (Windows-only,
  `cfg(windows)`) wraps the `windows-service` crate for
  `service {install,uninstall,run}` — not compiled on Linux, so it's
  validated by CI's `windows-latest` job. The phone-home loop runs on its
  own thread there since it never returns in normal operation; the SCM
  thread only waits for a stop signal (no in-loop graceful shutdown yet).

## Usage

```sh
cp executor.example.toml executor.toml
cargo run -- run cert.verify --param path=/path/to/cert.cer
# {"status":"running","percent":50.0,"phase":"verifying"}
# {"status":"done","percent":100.0,"result":{"chain_ok":false,"raw":""}}
# { "chain_ok": false, "raw": "" }
```

Each `--param key=value` becomes a command parameter; `--config` (default
`executor.toml`) selects which config file's `role` governs the dispatch.
A guest-role config rejects `powershell.exec_arbitrary` before any shell runs:

```sh
cargo run -- run powershell.exec_arbitrary --param script="echo hi"
# Error: role Guest lacks capability VmExecArbitrary required by 'powershell.exec_arbitrary'
```

To phone home instead of dispatching locally, fill in `identity.vm_id`,
`identity.agent_token`, and `backend.url` (from `POST /api/executor/register`
on the backend) in `executor.toml`, then:

```sh
cargo run -- connect --config executor.toml
```

On Windows, to install as a service (which calls the same phone-home loop):

```powershell
pki-executor.exe service install
```

## Testing

`cargo test` runs everything that doesn't require a real Windows box, a live
shell, or a live backend: config parsing, capability/role gating (including
the guest ↔ `VmExecArbitrary` invariant), every command handler driven
through a mock PowerShell executor, and the phone-home framing/dispatch
translation (`phonehome::handle_command`) driven through an in-memory
channel. Real `powershell.exe` invocation, a real WebSocket connection to a
running backend, and Windows Service Control Manager lifecycle are exercised
only in CI's `windows-latest` job / manual testing — see the CI workflow for
what actually runs where, and the top-level plan's Verification section for
the manual end-to-end phone-home walkthrough.

### Pre-commit hook

A pre-commit hook in `.githooks/pre-commit` mirrors CI's format, lint, and
test gates (`cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D
warnings`, and `cargo test --all-targets`) so failures are caught before they
reach CI. Enable it once per clone:

```
git config core.hooksPath .githooks
```

Bypass it for a single commit with `git commit --no-verify`.
