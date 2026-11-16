# tools.simplehelp.io publication

Public guide: https://simple-help.com/tools/agent-sudo
Tools hub: https://simple-help.com/tools
Legacy URL (compatibility forwarding page): https://tools.simplehelp.io/agent-sudo.html
Bootstrap: https://tools.simplehelp.io/agent-sudo/install.sh

1.0.4 is the current release. The exact release binaries are tested in disposable Ubuntu VMs. No development-host installation is part of publication. GitHub mirrors are published separately after the tools-host release is verified.

## Versioned release inputs

The exact original tested archive is retained unchanged:

- `agent-sudo/agent-sudo-0.1.0-linux-amd64.tar.gz`: `6738d229c29ecf033698eadcb3233baac71aac69b5e26f9570eb024ece3f0946`
- `agent-sudo/agent-sudo-0.1.0-source.tar.gz`: `1905d8afb409d432bd57d300262e3a6b4eb1a75c4e6d1d872b743098d3925a22`
- Package `.tar.gz.sha256`, `0.1.0-SHA256SUMS`, `0.1.0-VALIDATION.md`, `0.1.0-SECURITY_REVIEW.md`, `0.1.0-OPERATOR.md` accompany them.

Source snapshot is the original c16c9de implementation; website/bootstrap sources are maintained separately in this checkout. Versioned reports retain their original prepublication statements and dates. Do not repack an existing version to update its docs.

## Release ordering

1. Increment the package version; never republish a rebuilt existing version. Include `LICENSE`, `NOTICE` and current `THIRD_PARTY_NOTICES.txt` in both source and binary archives; verify dependency/toolchain notices against the exact new build. Build/test the next version in disposable VMs. Enforce exact binary hashes and inspect the archive/source allowlist. Exclude logs, keys, VM images, stale archives and private files. Produce source and checksums.
2. Use the authorised download-host publishing service and inspect its current schema before use. Publish each immutable versioned artifact with `operation: publish`, `public_release: true`, exact SHA-256 and one source field. The current Lore registry enforces a 64 KiB total input limit despite the action’s advertised 1 MiB base64 allowance; use a publisher-reachable `source_url` for larger files, and confirm reachability before submitting. The URL and any redirect/download target must be unsigned and contain no credentials or expiry/signature tokens; the service rejects signed landing-page links. Use a stable request ID for identical retries. Never overwrite a versioned archive; correct mistakes with a new version.
3. Wait for each asynchronous request via `lore services get ID`. Check both service and action status, download the returned public URLs anonymously and verify their exact hashes. Save sanitized receipts in `docs/publication/`; never save upload payloads containing credentials.
4. Update the version, archive name and SHA-256 in `website/install.sh`. Review the bootstrap and page; keep the machine-wide installation, private token handoff and grant invalidation explanations. Update the bootstrap with `operation: update` and `expected_previous_sha256` equal to the freshly verified current public hash. A stale hash is a conflict: investigate, do not overwrite blindly. Record the returned previous/current hashes.
5. Test the actual public bootstrap on both supported disposable VM configurations, including machine-wide installation, positional/prompted grants, normal sudo prompting, failure preservation and grant/run/revoke. No development-host or production-host install.
6. Coordinate any guide changes with the simple-help.com website owner after the verified downloads and bootstrap are available. Do not republish the legacy tools-host landing page. New CLI help and handoffs point to https://simple-help.com/tools/agent-sudo.
7. Record publication IDs, receipts, hashes and public test evidence; update CHANGELOG and file maps. Commit locally; pushing or GitHub releases are separate work.

Product pages live on simple-help.com/tools, separate from download hosting. The historical `website/agent-sudo.html` is retained as a reference; do not publish it to tools. Use `website/agent-sudo-redirect.html` to retire the old tools-host information page while preserving existing binary handoff links. Publish this forwarding file to `agent-sudo.html` under its freshly verified hash. Literal deletion is unsupported by tools_publish and needs the hosting operator. Scripts and other downloads are served as attachments. Files are verified and replaced atomically by SH Website; multi-file publication is ordered, not one atomic transaction. Artifacts precede bootstrap, which precedes the page. Rollback uses a checksum-guarded update of bootstrap/page to a previously verified version; it does not restore invalidated grants.

## Bootstrap trust and privileges

The one-line command is `curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh`. It streams the bootstrap to `sh`; the script needs no recipient, and sudo retains its normal terminal authentication. A single outer shell compound command must parse completely before execution; keep its closing brace as the final byte so every truncated prefix is incomplete or a harmless no-op. Package download, pinned checksum verification, temporary directory and cleanup are handled inside the bootstrap. HTTPS authenticates the hosting connection; the embedded SHA-256 pins the package. It is not a signature or protection from a compromised publisher/site. Downloads, checksum verification and extraction are unprivileged for a normal administrator. Only the verified package's existing offline installer is invoked through sudo; it independently validates payload, ownership, policy and supported sudo version. Installation selects no recipient. Administrative issuance later authorizes each account dynamically. Reinstallation invalidates all grants. Current release is 1.0.4; immutable 0.1.0 and 0.2.0 assets are retained.

## 0.1.0 historical public validation

Eight downloads (package, package checksum, matching source, three original reports, aggregate checksums and bootstrap) were fetched anonymously from their actual tools.simplehelp.io URLs and matched local exact-byte SHA-256 values. The aggregate metadata was corrected under the previous-hash precondition to use its actual public document filenames. No versioned archive was changed.

`python3 tests/vm/public_bootstrap.py` passed 15 checks in each disposable VM (30 total). It fetched the real public bootstrap, executed the exact page command with terminal stdin, selected a recipient different from the administrator, authenticated with normal sudo, installed the actual public package, enrolled the explicit complete multi-account list, issued and used grants, read status, revoked and denied reuse, checked both installed binary hashes, and removed the application. Injected curl failures for bootstrap/package downloads, bad package bytes, unsupported architecture/OS and a nonexistent recipient preserved managed files/configuration and did not call sudo. Fault cases are local PATH/OS fixtures; successful download/install cases use the actual public HTTPS endpoints.

Platforms remain Ubuntu 24.04.5 LTS amd64 / sudo 1.9.15p5 (1.9.15p5-3ubuntu5.24.04.4), and Ubuntu 26.04.1 LTS amd64 / sudo-rs 0.2.13 (0.2.13-0ubuntu1.2). These 30 checks supplement the original 202 compiled-binary VM checks; they are not another independent security audit. An earlier 30-check bootstrap preflight used simulated downloads and is deliberately excluded from the public-test count.

The source archive's 33 regular files match implementation commit c16c9de exactly; no debug/working logs, private keys, VM state, build directories or stale archives were included. Temporary artifact relays transported only the exact already-public-intended release bytes to SH Website; installed clients use only tools.simplehelp.io. The original LAN source was unreachable and the oversized inline API request was rejected before dispatch. The publication receipts and final public hash verification are recorded alongside this document.

Live browser verification passed: HTML renders with text/html and no attachment disposition; real clipboard write/read, denied-copy selection fallback, exact command text, responsive layouts and download URLs all passed without JavaScript errors. To repeat checks of the retained historical page source, run `PLAYWRIGHT_MODULE=/path/to/playwright node tests/website.cjs` with Playwright Chromium installed. The live compatibility URL now forwards to the separately maintained public guide; this historical-page test does not target that guide. Records and screenshots go under ignored target/. Test the live page's rendering MIME/disposition, real clipboard write/read, copy denial fallback, exact command text, 375/768/1280-pixel layouts and JavaScript errors. Public download hashes/MIME/disposition are in publication/download-verification.json; public VM results and sanitized service receipts are in the same directory.

Production-host testing is outside this publication workflow. No installation occurred on the development host; no GitHub release, push, recurring task or new release-management service was created.

## 0.2.0 publication — 2026-11-02

Implementation source snapshot: local commit `3efd484`; source archive SHA-256 `aa026b165bfe54928bdbb93203d54d94d1aa42154d7419dc8392b32c06252460`. The independently maintained website/bootstrap can receive later presentation and validation updates without changing those frozen implementation sources or binaries.

- Package: `agent-sudo/agent-sudo-0.2.0-linux-amd64.tar.gz`, SHA-256 `1bb0b9626aca32e8f4d07f61ea9a88791c27b20e0b10fb417495f4b8bce36329`.
- Bootstrap: `agent-sudo/install.sh`, SHA-256 `9bec6205b835cda61d537180717474525c2e6f401e52490ab9888760e44a52d2`.
- Immutable evidence: `0.2.0-VALIDATION.md`, `0.2.0-SECURITY_REVIEW.md`, `0.2.0-OPERATOR.md`, `0.2.0-PUBLIC_VALIDATION.md`; combined checksums use the exact original public filenames in `0.2.0-SHA256SUMS`.
- Seven immutable downloads verified before bootstrap update. Source relay requests with signed download links were rejected without mutation; unsigned direct relay URLs were independently hash-verified and accepted under fresh request IDs. Final installer uses only tools.simplehelp.io.
- Exact public command passed 18 checks in each VM (36 total), including real terminal sudo authentication, machine-wide install, positional grants/run/status/revoke, reinstall, binary hash identity and removal. Simulated download/checksum/truncation/platform cases preserved installation before sudo. All 2,598 proper prefixes of the actual hosted script were checked with marker shims and a full-script positive control.
- The short shell pipeline can return zero if curl fails before producing any script bytes; curl still emits the error and nothing is installed. Check the final installation message/version. Package failures after a full script return nonzero.

Sanitized 0.2.0 receipts, public download headers/hashes, installed-binary evidence and browser checks are stored in `docs/publication/0.2.0-*`. Immutable 0.1.0 assets remain unchanged. No production/development-host installation, GitHub push or GitHub release.

Final live page SHA-256: `e0cfdb32d826da37c3e2e66e55c39c83d60285cf7692e1ed7d8cd4097324ef06`. Actual Chromium checks passed at 375/768/1280 px: real clipboard write/read, denied-copy fallback, keyboard focus/activation, loaded brand fonts and inspected colors. Thirteen live URLs passed MIME/link/hash checks, including unchanged 0.1.0 package/source. Desktop and mobile viewport screenshots were visually compared with the live SimpleHelp reference.

## 1.0.0 publication — 2026-11-02

User-authorized 1.0 release: readable grant prompts/output, real calling account and 10-minute defaults, local expiry with timezone, explicit private token handoff and administrator revocation. The installer command stays exactly `curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh`. No runtime authorization, helper protocol or grant lifetime change. Installation/upgrades invalidate existing grants; an administrator must issue new tokens.

Versioned package/source/checksum/guides use `agent-sudo-1.0.0-*` and `1.0.0-*` under `https://tools.simplehelp.io/agent-sudo/`. Immutable assets are verified before mutable bootstrap/page updates; earlier version bytes remain untouched. Exact identities, installed VM/public results, fresh update preconditions and SH Website service receipts are recorded in `docs/publication/1.0.0-*`. The source archive is the frozen implementation snapshot; later public evidence and mutable website pointers are recorded in subsequent local commits. No GitHub push/release.

Verified 1.0 publication identities: source commit `b43b4ee0ef879ed1838907c9679ff274d89e8cb5`; package SHA-256 `8ef93794557f6dfe591622ecc95a391c1b6a5b49d9afd94ec6e1d946154e1f33`; source SHA-256 `5727fdc6ae99dab5bc8692a482db713dcdf9ccaca7f605c1fbb8b271881c312c`. Both VM environments passed 230 installed-binary checks and 36 exact public-command checks (18 per VM), including all 2,564 proper bootstrap byte prefixes with a complete-script positive control. Current bootstrap SHA-256: `d8090eedd3f0ffe0fae5f7f4bf13f83d0546fc5778e2f5885ac7547da5b0f769`. The page is updated only after public installation evidence is verified.

Final live page SHA-256: `89ac1380ddbd64652e812b969c88a51e58c2c78c694d1ef90a33e2347d160817`. Chromium verified actual clipboard contents, denial fallback, keyboard interaction and 375/768/1280 px layouts. Fifteen live URLs passed MIME/link/hash checks, including unchanged 0.1.0/0.2.0 packages and sources. Receipts cover all ten ordered publications/updates. Both disposable VMs were shut down after the tests.

## 1.0.1 publication — 2026-11-02

Creator-scoped `agent-sudo revoke all` is a distinct freshly authenticated administrative operation. Recipient `revoke --all` remains unchanged. Freeze and verify the new versioned package/source/checksum/guides before updating the pinned bootstrap, then test the literal public command in both VMs and update the page last. Preserve all earlier versioned files. Exact identities and sanitized receipts are stored under `docs/publication/1.0.1-*`. No production-host or development-host installation and no GitHub push/release. Installation/upgrades invalidate existing grants.

Frozen source commit: `1f0df087e62be36f5756995bb7c0a94f78f0ed19`. Package SHA-256: `beefb7afd69d4dd59c67c704518388c364e2384177edf527697e0878d48e2b02`; source archive SHA-256: `a9920651faa0cc96c200fe3647f4c7fb0f02d0271e0b73fa82a797b5377c078f`. Both binaries match the 254-check installed-VM evidence and reproduce identically from relocated locked sources. Public installation and page evidence are recorded after the guarded pointer updates.

Public bootstrap SHA-256: `568bacbc3572687c97700ad4e19878ff8434623716d75a99744e296b25e558c7`. Both disposable VMs passed 19 literal-public-command checks (38 total), including the new batch command and all 2,564 proper bootstrap prefixes. Old installed grants are invalidated on upgrade. Test VMs were powered off after public verification.

Final live page SHA-256: `802c45088bfd95b122764aa58f9d9371e276d3d92aa26fad2ca2b69f453500bf`. All ten SH Website publications/guarded updates completed. Chromium verified actual clipboard contents, denied-copy fallback, keyboard operation, creator/recipient scope instructions, branded fonts/colors and 375/768/1280 px layouts. Seventeen live URLs passed MIME/link/hash checks, including unchanged 0.1.0, 0.2.0 and 1.0.0 packages/sources. Sanitized receipts and browser/public-URL evidence are recorded under docs/publication/1.0.1-*.

## 1.0.2 publication attempt — 2026-11-02

Expanded command-line guide and `-h` shortcut; grant and helper behavior unchanged. 128 core VM checks and installed help checks passed. Publication is incomplete: SH Website declined the security guide citing private machine-specific operational details, and the operator guide upload was blocked by a transfer failure. Several versioned files, including an aggregate checksum file referencing the missing guides, were published. Installer and page remain on 1.0.1. The published 1.0.2 package and source contain a copy of the same security guide. The optional standalone guide is not required for the release; completion is recorded below. See `docs/publication/1.0.2-*` for identities and receipts. No GitHub push or release, and no Loom or development-host installation.

## 1.0.2 publication completion — 2026-11-03

The published 1.0.2 package matches SHA-256 `cd1e485336a43859bcc8559d21a11f519525649b86740d0b1416182781d61be0`. The installer was updated under the previous hash precondition and the exact public command passed in both disposable Ubuntu VMs. The public page remains on 1.0.1: SH Website could not transfer the revised page via either inline text or base64. The prepared page links to the existing 1.0.1 operator guide and omits links to unpublished optional documents. Earlier failed requests remain recorded for transparency. No production-host installation or GitHub release was performed.

## 1.0.3 publication preparation — 2026-11-04

Owner-authorized compact v2 tokens and `see: URL | TOKEN` terminal handoff. Frozen allowlisted source commit `6e694bdaea947a14ca3568aee1abab7bd8a63816`; package SHA-256 `c62253cdf3041a70cbde65593d38aa73c13c7955fdf21132c16f296a29e90565`. Eight native tests, 230 installed-binary VM checks, lint/MSRV/audit, exact relocated-source binary reproduction and archive manifest review passed. No installation on the development host or GitHub push/release. Public source and package exclude internal publication history; source paths are recorded in the artifact identity. Six immutable artifacts were submitted through SH Website before mutable installer/page updates. Publication remains pending until the completion evidence below.

## 1.0.3 publication completion — 2026-11-04

All six immutable artifacts were published and anonymously verified before the installer update. The exact public installation command passed 38 checks (19 in each disposable Ubuntu VM), including 2,564 proper bootstrap prefixes per VM and failure preservation. Installer SHA-256: `4085b3fd1ef8c9abcbabaf451dc9a19a6b01621faa054eb046ae34e6788f968f`. Final page SHA-256: `6bc5e2cf718cca4e907313faae6051e34e632f77cc6a4c4dc10b78024f2f3889`. The HTML relay rejected the page with HTTP 415; the supported direct-text service input succeeded. Eight successful publication/update receipts and public/browser evidence are in `docs/publication/1.0.3-*`.

Chromium verified live HTML MIME/disposition, real clipboard contents, denied-copy fallback, keyboard operation, brand fonts/colors and 375/768/1280 px layouts with no page errors. Nine final public download URLs were verified, including unchanged 1.0.1/1.0.2 packages. The handoff is 118 characters including its 67-character token; earlier chat estimates of 116 were corrected. Script stdout remains token-only. Upgrades invalidate existing grants.

The frozen source archive is the exact allowlisted commit in its artifact identity; a later test-only optional SSH/reboot harness grant-ID correction is recorded in local commit `82bac80`. Those SSH/reboot suites are excluded from this release's claimed 230 installed-binary checks. Production binaries were unchanged by that follow-up. Final review, deterministic clean-staging regression, exact source-file comparison and all publication verification passed. Test VMs were shut down; no development-host installation or GitHub push/release occurred.

## SimpleHelp guide migration — 2026-11-16

Product hub and guide now live at https://simple-help.com/tools and
https://simple-help.com/tools/agent-sudo. The old tools-host information page
was replaced by `website/agent-sudo-redirect.html` under the previous-file
hash precondition; anonymous HTTPS verified exact bytes and HTML rendering
headers. Existing 1.0.3 installer and versioned downloads remain unchanged.
CLI help/handoff changes are prepared in source and require a new binary
release to appear in installed copies. No new agent-sudo release was made.
