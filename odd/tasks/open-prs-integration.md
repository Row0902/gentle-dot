# The open-PR integration branch

`port/open-prs` is `feat/windows-port` plus every open PR of this repository as of 2026-10-22, merged
or disposed one by one. It exists so the port does not rot behind work already proposed, and so the
collisions between those proposals are visible **before** `main` absorbs them — it is not a proposal
to merge as one unit, and it is not part of the port's PR #57.

Base: `feat/windows-port` at `6b1ccbb`. Every PR head is available as `origin/pr/<number>`
(`git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'`).

## Dispositions

| PR | What it is | Files vs port | Disposition | Why |
| :--- | :--- | :--- | :--- | :--- |
| #49 | WebKitGTK DMA-BUF off on native Wayland | 7, 0 overlap-conflict | **merged** | Nothing in the port touches it; applied clean. |
| #56 | no proc-macro strip for macOS 27 | 1, 1 | **merged** | Clean; it is the same `[profile.release.build-override]` the port already carried. |
| #69 | `scripts/linux/setup-fedora.sh` | 5, 3 | **merged** | New script plus one docs sentence; our rewritten `docs/install.md` kept, the sentence re-applied. |
| #70 | shortcut fallback chain (#50) | 2, 2 | **merged, adapted** | Its mechanism (candidates, dedup by keys, persist the chosen fallback) is kept; `candidates()` is rewritten to include this platform's default first (`Os::CURRENT.default_shortcut()`, W9) and to drop the bare `F1`–`F5` candidates, which would take those keys from every app. Its two order-dependent tests are replaced by property tests. |
| #71 | links open in the browser, never in the panel (#42) | 4, 2 | **merged** | Its `on_navigation` block is the right tauri-2.12 API and the port had none; our `with_panel_effects` line kept, its block adopted; the UI half applied clean. |
| #72 | prefer the local recognizer in the UI | 2, 0 | **merged** | Clean; orthogonal to the port's native Parakeet path. |
| #74 | workspace gets its own git repository (#51) | 3, 3 | **merged** | `ensureGitBoundary` is absent from the port and the bug is real; conflict was the port's one-line import style, resolved by keeping the style and adding its `spawnSync`/`statSync`. |
| #75 | configurable LLM turn timeout (#52) | 9, 8 | **merged** | Clean, and it carries its own follow-up commit bounding the run. |
| #78 | pin `pi-codemode@1.0.4` (#64) | 2, 2 | **merged** | Clean; the port pins codemode at build time in `runtime-build.ts` (W30), so the two are complementary rather than equal. |
| #79 | WhatsApp bridge (Baileys/BuilderBot) | 3, 1 | **merged** | A whole new feature, not the ignore-file change it looked like from the outside: conflict was `.gitignore`, resolved as a union (our Engram ignore lines plus its hand-written `.d.ts` exception). |
| #61 | mobile PWA client | 18, 2 | **deferred** | `client.ts`'s `tokenFromLocation` changes from one storage to `{session, persistent}`, so every caller and test in the port has to move with it. That is new code in a feature branch of its own, not an integration. |
| #73 | voice without OpenAI (local Parakeet, NVIDIA TTS) | 10, 3 | **deferred** | The port already ships native Parakeet (`packages/ui/src/voice-native.ts`), so its `voice-tools` sidecar would add a second, unused engine and a model path; the NVIDIA TTS half is the only novel part and deserves its own slice. |
| #76 | hotkey chain + navigation | 6, 3 | **superseded** | Byte-identical `shortcut.rs`/`shell.rs` blobs to #77/#91, and its navigation code registers `on_navigation` on the built window and uses `WebviewNavigation::External`, neither of which exists in tauri 2.12. #71 does that half correctly and #70 the other. |
| #77 | macOS 27 Rust floor | 7, 4 | **one line of it kept** | Its `[profile.release.build-override] strip = false` was already in #56; only `rust-version = "1.99"` survived, and it is applied as its own commit because it raises the toolchain floor on **every** platform, not just macOS. Reviewer's call. |
| #80 | Niri/Wayland compatibility | 7 named, 3 overlap | **deferred** | 99 commits and a 2.3 MB diff spanning unrelated concerns (niri, request recovery, image budget, ignore rules). It has to be split before anyone can review or merge it. |
| #91 | grab-bag: CI, Makefile, Cargo, pi deps, whatsapp, mcp-proxy | 19, 10 | **superseded** | Its CI/Makefile/Cargo/shortcut halves duplicate #77/#76/#69, and its `pi-codemode` pin is moot next to the port's build-time pin. Its unique halves (whatsapp — now in #79 — and the mcp-proxy retry) belong in their own PR. |
| #94 | libayatana docs + NVIDIA key + fallback persist | 11, 3 | **superseded** | The shortcut half is a subset of #70 and the NVIDIA half a subset of #73; nothing survives on its own. |
| #95 | fallback shortcut list | 1, 1 | **superseded** | Same intent as #70 in a weaker form (no dedup by keys, no persistence) and it includes bare `F1`–`F5`, which a global hotkey would take from every app. |
| #97 | macOS/Linux CI (ours) | 1, 0 | **not merged here** | It is its own PR to `main` (issue #96) and merging it into the port branch would couple an infrastructure change to the port's review. |

## The rules this branch applied

1. **A PR that the port already answers is not merged.** It is recorded as superseded with the
   evidence, because a "merge" that keeps none of the other side is a lie in the history.
2. **A conflict is resolved in favour of whichever side is measurably right**, not in favour of
   ours by default: #71's navigation block replaced nothing of ours, #70's mechanism replaced ours,
   and #70's fallback list lost because a global `F1` is a user-visible harm.
3. **A PR whose integration means writing new code is deferred**, not silently adapted: #61 and #73
   need their authors' design against the port, not a conflict resolution.
4. **Nothing is claimed about behaviour until the suites run** (below).

## Defects the merges exposed in the PRs themselves

These are not integration costs. Each one means the PR, as opened, breaks the repository it targets:

- **#75 leaves `main` failing `pnpm typecheck`.** It adds `{ type: "turn_timeout"; timeoutMs: number }`
  to `ServerPayload` (`packages/protocol/src/index.ts:436`) and never adds a branch to the panel's
  exhaustive switch in `packages/ui/src/store.ts`, so `reduceServer` no longer returns on every path
  (TS2366). Measured here, not inferred: the case was absent from `origin/pr/75:packages/ui/src/store.ts`
  and the port only fails once the merge lands. This branch adds the missing case (stop streaming;
  the user-readable sentence arrives separately as an `error` with code `turn_timeout`).
- **#78 leaves its own test failing.** It pins `@earendil-works/pi-codemode` in
  `packages/daemon/package.json`, which adds an eighth entry to the staged runtime's dependency map,
  while `packages/daemon/test/runtime-build.test.ts` still asserts the seven it knew. The expectation is
  extended here, with the reason written next to it.

## Measurement

Windows 11 x86_64, after the merges and the three integration commits (`853ac76`, `c752801`).

| Check | Result | Port baseline (`6b1ccbb`) |
| :--- | :--- | :--- |
| `cargo test --lib` | **420 passed / 0 failed / 4 ignored** | 413 passed / 0 failed / 4 ignored |
| `pnpm typecheck` | **0 errors** | 0 errors |
| `pnpm lint` | **clean, 225 files** | clean on the tracked tree (locally 3 errors from `apps/engram-guard/target/` and `.atl`, which are build output, not sources) |
| `pnpm test`, full parallel run | 913 passed / 42 skipped / 956, **1 failed** | same class of flake, documented in the port plan |

The single failure is the class this plan already records, and it is not caused by any merge: `mcp-proxy.test.ts` fails with `TypeError: fetch failed / Error: bad port` from pi-mcp's streamable-http transport, and the previous run failed the same way in `connector-secrets.test.ts` — a different file, same signature. Run in series, both pass: `pnpm vitest run --no-file-parallelism packages/daemon/test/mcp-proxy.test.ts packages/daemon/test/connector-secrets.test.ts` → **32 passed / 1 skipped, exit 0**. The honest baseline for this host is therefore "MCP-proxy tests are unstable under full parallelism, green in series", exactly like the daemon suite the port already documents.

### What the merges cost, in code

Three commits exist because the merged PRs alone leave the tree red, and none of them is a port defect:

1. `853ac76` — the panel's `turn_timeout` branch (#75's missing typecheck case) and the eighth dependency in `runtime-build.test.ts` (#78).
2. `c752801` — biome's formatter and two unused imports across `bridge.ts`, `config.ts`, `whatsapp-bridge.ts`, `config.test.ts`, `isolation.test.ts` and `runtime-build.test.ts`; the PRs were opened without running `pnpm lint`.
3. The `shortcut.rs` test type error, fixed inside #70's own merge commit: `list.iter().skip(2).eq(...)` compared `&String` with `&str`.

## Cross-platform CI: all three platforms green (run `39871077755`, `39871077752`)

The integration branch was pushed to the fork with the POSIX channel merged in, and the runners found what no local measurement could — three defects in two runs, none of them visible from a Windows machine:

| Job | First run | Final run |
| :--- | :--- | :--- |
| Rust `windows-latest` | success, 420 tests | success |
| TypeScript `ubuntu-latest` | success | **940 passed / 16 skipped** |
| TypeScript `macos-latest` | success | **940 passed / 16 skipped** |
| TypeScript `windows-latest` | **failure: PR #74** | success |
| Rust `ubuntu-latest` | **failure: `E0425`** (and one run cancelled) | **425 passed / 6 ignored** |
| Rust `macos-latest` | **failure: `E0425`**, then a failing test | **431 passed / 4 ignored** |

- **The port did not compile on macOS or Linux at all**, and this is the finding that matters beyond this branch: `src/daemon.rs:491` sits inside `if cfg!(windows)`, and `cfg!()` is a **runtime** test, so both branches are compiled on every platform — while `holds_git` (W31, W34) was behind `#[cfg(windows)]`. `E0425` stopped the build before any other code was reached. Fixed by making the function unconditional, and the same one-line fix is now on `feat/windows-port` (`4b7877d`), because PR #57 claimed a cross-platform build that no runner had ever checked.
- **PR #74's two boundary tests fail on a Windows runner**: `git rev-parse --show-toplevel` answers with the long path while the fixture's temp folder is `C:\Users\RUNNER~1\…`, and the assertions compared them raw. Fixed with `realpathSync.native`, which expands NTFS 8.3 names; the local machine never saw it because its `TEMP` has no short form.
- The `Rust (ubuntu-latest)` job of run `39869942335` reads **cancelled**, not failed: the workflow has `cancel-in-progress: true` and that run was superseded by a docs-only push. Linux had no verdict until run `39871077755`. Recorded because a cancelled job looks like a green one in a summary table and is the opposite of evidence.
- The MCP-proxy `bad port` flake did **not** appear on any runner: that instability is this host's, and the suite is green in CI on ubuntu and macOS — Windows too, after the #74 fix.

### What this branch does not claim

Nothing here is a macOS or Linux measurement: the macOS-only arms of #56/#77 and the Linux arms of #49/#69 have not been compiled by this run. PR #97's CI (`ci/linux-macos`) is the channel for that, and it is separate on purpose.
