# tools.simplehelp.io publication

Public page: https://tools.simplehelp.io/agent-sudo.html
Bootstrap: https://tools.simplehelp.io/agent-sudo/install.sh

1.0.1 is the current release. The exact release binaries are tested in disposable Ubuntu VMs. A Loom 0.2.0 root-command smoke test passed; its user-requested expiry recheck is pending. No Loom/development-host installation, GitHub push or GitHub release is part of this publication.

## Versioned release inputs

The exact original tested archive is retained unchanged:

- `agent-sudo/agent-sudo-0.1.0-linux-amd64.tar.gz`: `6738d229c29ecf033698eadcb3233baac71aac69b5e26f9570eb024ece3f0946`
- `agent-sudo/agent-sudo-0.1.0-source.tar.gz`: `1905d8afb409d432bd57d300262e3a6b4eb1a75c4e6d1d872b743098d3925a22`
- Package `.tar.gz.sha256`, `0.1.0-SHA256SUMS`, `0.1.0-VALIDATION.md`, `0.1.0-SECURITY_REVIEW.md`, `0.1.0-OPERATOR.md` accompany them.

Source snapshot is the original c16c9de implementation; website/bootstrap sources are maintained separately in this checkout. Versioned reports retain their original prepublication statements and dates. Do not repack an existing version to update its docs.

## Release ordering

1. Increment the package version; never republish a rebuilt existing version. Build/test the next version in disposable VMs. Enforce exact binary hashes and inspect the archive/source allowlist. Exclude logs, keys, VM images, stale archives and private files. Produce source and checksums.
2. Discover `lore services list --agent sh-website --owner antony --action tools_publish` before use. Publish each immutable versioned artifact with `operation: publish`, `public_release: true`, exact SHA-256 and one source field. The current Lore registry enforces a 64 KiB total input limit despite the action’s advertised 1 MiB base64 allowance; use a publisher-reachable `source_url` for larger files, and confirm reachability before submitting. The URL and any redirect/download target must be unsigned and contain no credentials or expiry/signature tokens; the service rejects signed landing-page links. Use a stable request ID for identical retries. Never overwrite a versioned archive; correct mistakes with a new version.
3. Wait for each asynchronous request via `lore services get ID`. Check both service and action status, download the returned public URLs anonymously and verify their exact hashes. Save sanitized receipts in `docs/publication/`; never save upload payloads containing credentials.
4. Update the version, archive name and SHA-256 in `website/install.sh`. Review the bootstrap and page; keep the machine-wide installation, private token handoff and grant invalidation explanations. Update the bootstrap with `operation: update` and `expected_previous_sha256` equal to the freshly verified current public hash. A stale hash is a conflict: investigate, do not overwrite blindly. Record the returned previous/current hashes.
5. Test the actual public bootstrap on both supported disposable VM configurations, including machine-wide installation, positional/prompted grants, normal sudo prompting, failure preservation and grant/run/revoke. No development-host or Loom install.
6. Update `agent-sudo.html` last using the same checksum precondition. Test HTML MIME/disposition, links/hashes, mobile/desktop rendering, copy success/failure and absence of browser errors. The page remains a preview until deployment validation warrants changing that statement.
7. Record publication IDs, receipts, hashes and public test evidence; update CHANGELOG and file maps. Commit locally; pushing or GitHub releases are separate work.

Use `agent-sudo.html`: tools_publish prohibits `index.html`; no directory listing or `/agent-sudo/` landing-page alias is needed. HTML renders with text/html; scripts and other downloads are served as attachments. Files are verified and replaced atomically by SH Website; multi-file publication is ordered, not one atomic transaction. Artifacts precede bootstrap, which precedes the page. Rollback uses a checksum-guarded update of bootstrap/page to a previously verified version; it does not restore invalidated grants.

## Bootstrap trust and privileges

The one-line command is `curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh`. It streams the bootstrap to `sh`; the script needs no recipient, and sudo retains its normal terminal authentication. A single outer shell compound command must parse completely before execution; keep its closing brace as the final byte so every truncated prefix is incomplete or a harmless no-op. Package download, pinned checksum verification, temporary directory and cleanup are handled inside the bootstrap. HTTPS authenticates the hosting connection; the embedded SHA-256 pins the package. It is not a signature or protection from a compromised publisher/site. Downloads, checksum verification and extraction are unprivileged for a normal administrator. Only the verified package's existing offline installer is invoked through sudo; it independently validates payload, ownership, policy and supported sudo version. Installation selects no recipient. Administrative issuance later authorizes each account dynamically. Reinstallation invalidates all grants. Current release is 1.0.1; immutable 0.1.0 and 0.2.0 assets are retained.

## 0.1.0 historical public validation

Eight downloads (package, package checksum, matching source, three original reports, aggregate checksums and bootstrap) were fetched anonymously from their actual tools.simplehelp.io URLs and matched local exact-byte SHA-256 values. The aggregate metadata was corrected under the previous-hash precondition to use its actual public document filenames. No versioned archive was changed.

`python3 tests/vm/public_bootstrap.py` passed 15 checks in each disposable VM (30 total). It fetched the real public bootstrap, executed the exact page command with terminal stdin, selected a recipient different from the administrator, authenticated with normal sudo, installed the actual public package, enrolled the explicit complete multi-account list, issued and used grants, read status, revoked and denied reuse, checked both installed binary hashes, and removed the application. Injected curl failures for bootstrap/package downloads, bad package bytes, unsupported architecture/OS and a nonexistent recipient preserved managed files/configuration and did not call sudo. Fault cases are local PATH/OS fixtures; successful download/install cases use the actual public HTTPS endpoints.

Platforms remain Ubuntu 24.04.5 LTS amd64 / sudo 1.9.15p5 (1.9.15p5-3ubuntu5.24.04.4), and Ubuntu 26.04.1 LTS amd64 / sudo-rs 0.2.13 (0.2.13-0ubuntu1.2). These 30 checks supplement the original 202 compiled-binary VM checks; they are not another independent security audit. An earlier 30-check bootstrap preflight used simulated downloads and is deliberately excluded from the public-test count.

The source archive's 33 regular files match implementation commit c16c9de exactly; no debug/working logs, private keys, VM state, build directories or stale archives were included. Temporary artifact relays transported only the exact already-public-intended release bytes to SH Website; installed clients use only tools.simplehelp.io. The original LAN source was unreachable and the oversized inline API request was rejected before dispatch. The publication receipts and final public hash verification are recorded alongside this document.

Live browser verification passed: HTML renders with text/html and no attachment disposition; real clipboard write/read, denied-copy selection fallback, exact command text, responsive layouts and download URLs all passed without JavaScript errors. To repeat, run `PLAYWRIGHT_MODULE=/path/to/playwright node tests/website.cjs https://tools.simplehelp.io/agent-sudo.html` with Playwright Chromium installed. Records and screenshots go under ignored target/. Test the live page's rendering MIME/disposition, real clipboard write/read, copy denial fallback, exact command text, 375/768/1280-pixel layouts and JavaScript errors. Public download hashes/MIME/disposition are in publication/download-verification.json; public VM results and sanitized service receipts are in the same directory.

Loom testing is pending. No installation occurred on the development host; no GitHub release, push, recurring task or new release-management service was created.

## 0.2.0 publication — 2026-11-02

Implementation source snapshot: local commit `3efd484`; source archive SHA-256 `aa026b165bfe54928bdbb93203d54d94d1aa42154d7419dc8392b32c06252460`. The independently maintained website/bootstrap can receive later presentation and validation updates without changing those frozen implementation sources or binaries.

- Package: `agent-sudo/agent-sudo-0.2.0-linux-amd64.tar.gz`, SHA-256 `1bb0b9626aca32e8f4d07f61ea9a88791c27b20e0b10fb417495f4b8bce36329`.
- Bootstrap: `agent-sudo/install.sh`, SHA-256 `9bec6205b835cda61d537180717474525c2e6f401e52490ab9888760e44a52d2`.
- Immutable evidence: `0.2.0-VALIDATION.md`, `0.2.0-SECURITY_REVIEW.md`, `0.2.0-OPERATOR.md`, `0.2.0-PUBLIC_VALIDATION.md`; combined checksums use the exact original public filenames in `0.2.0-SHA256SUMS`.
- Seven immutable downloads verified before bootstrap update. Source relay requests with signed download links were rejected without mutation; unsigned direct relay URLs were independently hash-verified and accepted under fresh request IDs. Final installer uses only tools.simplehelp.io.
- Exact public command passed 18 checks in each VM (36 total), including real terminal sudo authentication, machine-wide install, positional grants/run/status/revoke, reinstall, binary hash identity and removal. Simulated download/checksum/truncation/platform cases preserved installation before sudo. All 2,598 proper prefixes of the actual hosted script were checked with marker shims and a full-script positive control.
- The short shell pipeline can return zero if curl fails before producing any script bytes; curl still emits the error and nothing is installed. Check the final installation message/version. Package failures after a full script return nonzero.

Sanitized 0.2.0 receipts, public download headers/hashes, installed-binary evidence and browser checks are stored in `docs/publication/0.2.0-*`. Immutable 0.1.0 assets remain unchanged. No Loom/development-host installation, GitHub push or GitHub release.

Final live page SHA-256: `e0cfdb32d826da37c3e2e66e55c39c83d60285cf7692e1ed7d8cd4097324ef06`. Actual Chromium checks passed at 375/768/1280 px: real clipboard write/read, denied-copy fallback, keyboard focus/activation, loaded brand fonts and inspected colors. Thirteen live URLs passed MIME/link/hash checks, including unchanged 0.1.0 package/source. Desktop and mobile viewport screenshots were visually compared with the live SimpleHelp reference.

## 1.0.0 publication — 2026-11-02

User-authorized 1.0 release: readable grant prompts/output, real calling account and 10-minute defaults, local expiry with timezone, explicit private token handoff and administrator revocation. The installer command stays exactly `curl -fsSL https://tools.simplehelp.io/agent-sudo/install.sh | sh`. No runtime authorization, helper protocol or grant lifetime change. Installation/upgrades invalidate existing grants; an administrator must issue new tokens.

Versioned package/source/checksum/guides use `agent-sudo-1.0.0-*` and `1.0.0-*` under `https://tools.simplehelp.io/agent-sudo/`. Immutable assets are verified before mutable bootstrap/page updates; earlier version bytes remain untouched. Exact identities, installed VM/public results, fresh update preconditions and SH Website service receipts are recorded in `docs/publication/1.0.0-*`. The source archive is the frozen implementation snapshot; later public evidence and mutable website pointers are recorded in subsequent local commits. No GitHub push/release.

Verified 1.0 publication identities: source commit `b43b4ee0ef879ed1838907c9679ff274d89e8cb5`; package SHA-256 `8ef93794557f6dfe591622ecc95a391c1b6a5b49d9afd94ec6e1d946154e1f33`; source SHA-256 `5727fdc6ae99dab5bc8692a482db713dcdf9ccaca7f605c1fbb8b271881c312c`. Both VM environments passed 230 installed-binary checks and 36 exact public-command checks (18 per VM), including all 2,564 proper bootstrap byte prefixes with a complete-script positive control. Current bootstrap SHA-256: `d8090eedd3f0ffe0fae5f7f4bf13f83d0546fc5778e2f5885ac7547da5b0f769`. The page is updated only after public installation evidence is verified.

Final live page SHA-256: `89ac1380ddbd64652e812b969c88a51e58c2c78c694d1ef90a33e2347d160817`. Chromium verified actual clipboard contents, denial fallback, keyboard interaction and 375/768/1280 px layouts. Fifteen live URLs passed MIME/link/hash checks, including unchanged 0.1.0/0.2.0 packages and sources. Receipts cover all ten ordered publications/updates. Both disposable VMs were shut down after the tests.

## 1.0.1 publication — 2026-11-02

Creator-scoped `agent-sudo revoke all` is a distinct freshly authenticated administrative operation. Recipient `revoke --all` remains unchanged. Freeze and verify the new versioned package/source/checksum/guides before updating the pinned bootstrap, then test the literal public command in both VMs and update the page last. Preserve all earlier versioned files. Exact identities and sanitized receipts are stored under `docs/publication/1.0.1-*`. No Loom or development-host installation and no GitHub push/release. Installation/upgrades invalidate existing grants.

Frozen source commit: `1f0df087e62be36f5756995bb7c0a94f78f0ed19`. Package SHA-256: `beefb7afd69d4dd59c67c704518388c364e2384177edf527697e0878d48e2b02`; source archive SHA-256: `a9920651faa0cc96c200fe3647f4c7fb0f02d0271e0b73fa82a797b5377c078f`. Both binaries match the 254-check installed-VM evidence and reproduce identically from relocated locked sources. Public installation and page evidence are recorded after the guarded pointer updates.

Public bootstrap SHA-256: `568bacbc3572687c97700ad4e19878ff8434623716d75a99744e296b25e558c7`. Both disposable VMs passed 19 literal-public-command checks (38 total), including the new batch command and all 2,564 proper bootstrap prefixes. Old installed grants are invalidated on upgrade. Test VMs were powered off after public verification.

Final live page SHA-256: `802c45088bfd95b122764aa58f9d9371e276d3d92aa26fad2ca2b69f453500bf`. All ten SH Website publications/guarded updates completed. Chromium verified actual clipboard contents, denied-copy fallback, keyboard operation, creator/recipient scope instructions, branded fonts/colors and 375/768/1280 px layouts. Seventeen live URLs passed MIME/link/hash checks, including unchanged 0.1.0, 0.2.0 and 1.0.0 packages/sources. Sanitized receipts and browser/public-URL evidence are recorded under docs/publication/1.0.1-*.
