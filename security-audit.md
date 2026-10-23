# Security Audit Report

**Account audited:** [HeziLiu](https://github.com/HeziLiu)
**Data snapshot:** 2026-10-22
**Purpose:** Quarterly security review — account posture plus pip-ecosystem advisory homework
**Scope:** (1) full repository inventory, (2) secret scanning alert status per repository, (3) current critical/high severity advisories in GitHub's advisory database for Python (pip) packages

## Repository Inventory

Four repositories were found under the account (source repositories plus forks). Each default branch was confirmed directly against the repository's branch list, not inferred.

| # | Repository | Default branch | Visibility | Type | Primary language | Last push |
|---|------------|----------------|------------|------|------------------|-----------|
| 1 | [Little-rookie](https://github.com/HeziLiu/Little-rookie) | `master` | public | source | Java | 2019-06-02 |
| 2 | [Big-Buzzard](https://github.com/HeziLiu/Big-Buzzard) | `master` | public | source | none reported | 2018-05-17 |
| 3 | [CodingInterviewChinese2](https://github.com/HeziLiu/CodingInterviewChinese2) | `master` | public | fork | C++ | 2018-12-28 |
| 4 | [awesome-chatgpt-prompts-zh](https://github.com/HeziLiu/awesome-chatgpt-prompts-zh) | `main` | public | fork | none reported | 2023-04-14 |

**Totals:** 4 repositories — 2 source repositories (Little-rookie, Big-Buzzard) and 2 forks (CodingInterviewChinese2, awesome-chatgpt-prompts-zh). All are public; none are archived.

**Inventory observations:**

- Two of the four repositories have had no push since 2019 or earlier. `Big-Buzzard` reports an empty tree and has been dormant since 2018.
- Only one repository is confirmed to hold original work (`Little-rookie`, Java coursework). The remaining activity is a C++ fork and a prompt-collection fork.
- No private repositories were visible to the credentials used for this audit; the inventory above reflects everything reachable.

## Secret Scanning Findings

Secret scanning alerts were queried for **every repository in the inventory**, in both the `open` state and the `resolved` state. **All eight requests were denied** by the GitHub API with HTTP `403 Resource not accessible by personal access token`.

| Repository | Open alerts | Resolved alerts | Verdict |
|------------|-------------|-----------------|---------|
| Little-rookie | not retrievable — 403 | not retrievable — 403 | Inconclusive |
| Big-Buzzard | not retrievable — 403 | not retrievable — 403 | Inconclusive |
| CodingInterviewChinese2 | not retrievable — 403 | not retrievable — 403 | Inconclusive |
| awesome-chatgpt-prompts-zh | not retrievable — 403 | not retrievable — 403 | Inconclusive |

**Important — read this before quoting numbers in the presentation:**

- **No repository could be confirmed clean.** A 403 response is an authorization failure, not an empty alert list. Absence of data must not be presented as absence of findings.
- **No repository could be confirmed to have alerts either.** Nothing here implies a leak.
- The failure is uniform across all four repositories and both alert states, which points to the token lacking the required secret-scanning scope (e.g. `security_events` / secret scanning alerts read access) rather than to any per-repository setting.
- Consequently it also cannot be determined from this pass whether secret scanning is enabled at all on any of these repositories.

**Net status for the review:** 4 of 4 repositories have an **unknown** secret scanning posture. This is the single largest gap in this report and should be closed before the presentation (see Recommendations).

## Advisory Highlights

From the current critical and high severity listings for the `pip` ecosystem, the three advisories judged most severe are below. All three were selected because each is rated **critical** and each results in attacker-controlled command execution rather than only a crash or information disclosure.

| Rank | Advisory ID | Severity | Affected package | CVSS | Headline |
|------|-------------|----------|------------------|------|----------|
| 1 | GHSA-v9pv-5gc8-w2m6 | critical | Pillow | 9.8 | Multi-frame loaders reuse stale native image storage after mode transitions — out-of-bounds write with demonstrated command execution |
| 2 | GHSA-w5f2-9q9c-ff4h | critical | lmcache | 9.8 | Unauthenticated remote code execution via pickle deserialization on the multiprocess ZeroMQ transport |
| 3 | GHSA-h4mw-j7qp-8mwm | critical | claude-agent-sdk | not published (critical) | Argument injection through the `resume` option yields arbitrary command execution |

**Selection rationale.** Both GHSA-v9pv-5gc8-w2m6 and GHSA-w5f2-9q9c-ff4h carry a 9.8 CVSS score with network-exploitable, no-authentication, no-user-interaction vectors and a proven code-execution impact. GHSA-v9pv-5gc8-w2m6 is ranked first over GHSA-w5f2-9q9c-ff4h on blast radius: Pillow is one of the most widely installed Python packages and the affected versions (11.0.0 through 12.x) include current releases, whereas lmcache is confined to LLM inference infrastructure. GHSA-h4mw-j7qp-8mwm is third: it is also a critical command-execution bug, but it requires an application to forward untrusted input into the SDK's `resume` option, making it a narrower trigger condition than a crafted image file or a reachable network port.

### Deep dive: GHSA-v9pv-5gc8-w2m6 (judged most severe)

- **Advisory ID:** GHSA-v9pv-5gc8-w2m6
- **CVE:** CVE-2026-96639
- **Severity:** critical — CVSS 3.1 score **9.8**, vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWEs:** CWE-125 (Out-of-bounds Read), CWE-787 (Out-of-bounds Write)
- **Published:** 2026-10-22 (NVD 2026-10-21)
- **Reported by:** Rotem Kama

**What the vulnerability actually is.** Pillow's multi-frame image loaders can keep the native `ImagingCore` storage that was allocated for one frame while simultaneously changing the Python-side image `mode` and decoder tiles for a later frame. The root cause is in `ImageFile.load_prepare()`, which only reallocates native storage when `_im is None` and never verifies that the retained native storage still matches `self.mode` and `self.size`. Several multi-frame `seek()` / `_open()` paths update `self._mode` and the decoder tiles for a later frame without invalidating `_im`, so the decoder then writes or reads using the new frame's mode while the native buffer still belongs to the old frame's mode.

Concretely: if frame 0 allocates storage for a narrow mode such as `L`, and a later frame of the same dimensions switches to a wider mode such as `RGB` or `CMYK`, Pillow decodes the wider pixels into the stale narrow native buffer. The result is native out-of-bounds writes, over-reads, and process crashes. Verified affected loader surfaces are **PSD, MPO/JPEG, DCX, and MIC**; TIFF is unaffected because its `seek()` path already checks both size and mode before reusing storage. The strongest demonstrated impact is command execution in the MPO/JPEG path, reachable through Pillow's own documented `ImageSequence.Iterator` + `frame.load()` usage, reproduced on Pillow 12.3.0 — including against an unauthenticated web upload service, where a single HTTP request with no user interaction triggered the marker command successfully 10 of 10 times.

**Affected package and versions.** Package `Pillow` (pip ecosystem). Vulnerable range: **`>= 11.0.0, < 13.0.0`**.

**Do patched versions exist?** **Yes.** The first patched version is **13.0.0**. The fix landed via [python-pillow/Pillow#10105](https://github.com/python-pillow/Pillow/pull/10105) (commit `78d97d994579aef81aafe123773d525f40f2522a`) and is included in the [13.0.0 release](https://github.com/python-pillow/Pillow/releases/tag/13.0.0). Upgrading to 13.0.0 or later resolves this advisory.

**Why this one leads the list.** Highest published score in the set (9.8), a fully unauthenticated network vector with no user interaction, code execution rather than merely a crash, an affected version window that covers currently shipping releases, and a package that is near-universal in Python image-handling code — particularly upload handlers, thumbnailers and preview pipelines that consume user-supplied files.

## Recommendations

Prioritized; work top to bottom.

1. **Upgrade Pillow to 13.0.0 or later everywhere images from untrusted sources are opened.** Closes GHSA-v9pv-5gc8-w2m6, the most severe finding in this report. Any upload handler, thumbnailer or preview pipeline that calls `Image.open()` / `.load()` on user-supplied files is in scope. Audit lockfiles for the `>= 11.0.0, < 13.0.0` window.
2. **Close the secret scanning gap before presenting.** Every one of the four repositories returned an inconclusive result because of token permissions. Re-run the checks with a token carrying the secret-scanning read scope so the review has real numbers instead of four question marks. Until then, present this as "not yet verified" rather than "clean."
3. **Patch lmcache to 0.5.6 or later (GHSA-w5f2-9q9c-ff4h).** Confirm the multiprocess transport is not bound to a routable address. If it ever was reachable from an untrusted network, treat the host as potentially compromised: review connections, check for unexpected processes, and rotate exposed credentials. Official images ran as root, so exposure is worse than it looks.
4. **Upgrade claude-agent-sdk to 0.2.121 or later (GHSA-h4mw-j7qp-8mwm)** wherever application code can pass untrusted input into the `resume` option.
5. **Enable secret scanning and push protection on all four repositories, forks included.** Push protection stops credentials at commit time rather than discovering them afterwards. This is the cheapest control on this list and it directly addresses the unknown in the findings table.
6. **Retire dormant repositories.** `Big-Buzzard` is empty and untouched since 2018; `CodingInterviewChinese2` is a fork untouched since 2019. Archiving or deleting them shrinks the account's attack surface and the surface that has to be audited each quarter.
7. **Turn on Dependabot alerts and security updates on the remaining active repository** so pip advisories surface automatically instead of being discovered during a quarterly manual pass.
