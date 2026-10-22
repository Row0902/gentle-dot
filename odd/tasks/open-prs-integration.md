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

Filled in by the runs recorded at the end of this branch.
