# tools.simplehelp.io publication

Public page: https://tools.simplehelp.io/agent-sudo.html
Bootstrap: https://tools.simplehelp.io/agent-sudo/install.sh

0.1.0 is a development preview, tested only in disposable Ubuntu VMs. Loom testing is pending. No GitHub release or Loom/development-host installation is part of this publication.

## Versioned release inputs

The exact original tested archive is retained unchanged:

- `agent-sudo/agent-sudo-0.1.0-linux-amd64.tar.gz`: `6738d229c29ecf033698eadcb3233baac71aac69b5e26f9570eb024ece3f0946`
- `agent-sudo/agent-sudo-0.1.0-source.tar.gz`: `1905d8afb409d432bd57d300262e3a6b4eb1a75c4e6d1d872b743098d3925a22`
- Package `.tar.gz.sha256`, `0.1.0-SHA256SUMS`, `0.1.0-VALIDATION.md`, `0.1.0-SECURITY_REVIEW.md`, `0.1.0-OPERATOR.md` accompany them.

Source snapshot is the original c16c9de implementation; website/bootstrap sources are maintained separately in this checkout. Versioned reports retain their original prepublication statements and dates. Do not repack an existing version to update its docs.

## Release ordering

1. Increment the package version; never republish a rebuilt existing version. Build/test the next version in disposable VMs. Enforce exact binary hashes and inspect the archive/source allowlist. Exclude logs, keys, VM images, stale archives and private files. Produce source and checksums.
2. Discover `lore services list --agent sh-website --owner antony --action tools_publish` before use. Publish each immutable versioned artifact with `operation: publish`, `public_release: true`, exact SHA-256 and one source field. The current Lore registry enforces a 64 KiB total input limit despite the action’s advertised 1 MiB base64 allowance; use a publisher-reachable `source_url` for larger files, and confirm reachability before submitting. Use a stable request ID for identical retries. Never overwrite a versioned archive; correct mistakes with a new version.
3. Wait for each asynchronous request via `lore services get ID`. Check both service and action status, download the returned public URLs anonymously and verify their exact hashes. Save sanitized receipts in `docs/publication/`; never save upload payloads containing credentials.
4. Update the version, archive name and SHA-256 in `website/install.sh`. Review the bootstrap and page; keep the complete enrollment and grant invalidation warnings. Update the bootstrap with `operation: update` and `expected_previous_sha256` equal to the freshly verified current public hash. A stale hash is a conflict: investigate, do not overwrite blindly. Record the returned previous/current hashes.
5. Test the actual public bootstrap on both supported disposable VM configurations, including explicit/interactive enrollment, normal sudo prompting, failure preservation and grant/run/revoke. No development-host or Loom install.
6. Update `agent-sudo.html` last using the same checksum precondition. Test HTML MIME/disposition, links/hashes, mobile/desktop rendering, copy success/failure and absence of browser errors. The page remains a preview until deployment validation warrants changing that statement.
7. Record publication IDs, receipts, hashes and public test evidence; update CHANGELOG and file maps. Commit locally; pushing or GitHub releases are separate work.

Use `agent-sudo.html`: tools_publish prohibits `index.html`; no directory listing or `/agent-sudo/` landing-page alias is needed. HTML renders with text/html; scripts and other downloads are served as attachments. Files are verified and replaced atomically by SH Website; multi-file publication is ordered, not one atomic transaction. Artifacts precede bootstrap, which precedes the page. Rollback uses a checksum-guarded update of bootstrap/page to a previously verified version; it does not restore invalidated grants.

## Bootstrap trust and privileges

The one-line command downloads a bootstrap into a fresh temporary file and runs it with terminal stdin intact. HTTPS authenticates the hosting connection; the embedded SHA-256 pins the package. It is not a signature or protection from a compromised publisher/site. Downloads, checksum verification and extraction are unprivileged for a normal administrator. Only the verified package's existing offline installer is invoked through sudo; it independently validates payload, ownership, policy and supported sudo version. Explicit existing recipients are mandatory; the full list replaces prior enrollment, invalidating all grants. Re-running currently installs 0.1.0.

## 2026-11-02 public validation

Eight downloads (package, package checksum, matching source, three original reports, aggregate checksums and bootstrap) were fetched anonymously from their actual tools.simplehelp.io URLs and matched local exact-byte SHA-256 values. The aggregate metadata was corrected under the previous-hash precondition to use its actual public document filenames. No versioned archive was changed.

`python3 tests/vm/public_bootstrap.py` passed 15 checks in each disposable VM (30 total). It fetched the real public bootstrap, executed the exact page command with terminal stdin, selected a recipient different from the administrator, authenticated with normal sudo, installed the actual public package, enrolled the explicit complete multi-account list, issued and used grants, read status, revoked and denied reuse, checked both installed binary hashes, and removed the application. Injected curl failures for bootstrap/package downloads, bad package bytes, unsupported architecture/OS and a nonexistent recipient preserved managed files/configuration and did not call sudo. Fault cases are local PATH/OS fixtures; successful download/install cases use the actual public HTTPS endpoints.

Platforms remain Ubuntu 24.04.5 LTS amd64 / sudo 1.9.15p5 (1.9.15p5-3ubuntu5.24.04.4), and Ubuntu 26.04.1 LTS amd64 / sudo-rs 0.2.13 (0.2.13-0ubuntu1.2). These 30 checks supplement the original 202 compiled-binary VM checks; they are not another independent security audit. An earlier 30-check bootstrap preflight used simulated downloads and is deliberately excluded from the public-test count.

The source archive's 33 regular files match implementation commit c16c9de exactly; no debug/working logs, private keys, VM state, build directories or stale archives were included. Temporary artifact relays transported only the exact already-public-intended release bytes to SH Website; installed clients use only tools.simplehelp.io. The original LAN source was unreachable and the oversized inline API request was rejected before dispatch. The publication receipts and final public hash verification are recorded alongside this document.

Live browser verification passed: HTML renders with text/html and no attachment disposition; real clipboard write/read, denied-copy selection fallback, exact command text, responsive layouts and download URLs all passed without JavaScript errors. To repeat, run `PLAYWRIGHT_MODULE=/path/to/playwright node tests/website.cjs https://tools.simplehelp.io/agent-sudo.html` with Playwright Chromium installed. Records and screenshots go under ignored target/. Test the live page's rendering MIME/disposition, real clipboard write/read, copy denial fallback, exact command text, 375/768/1280-pixel layouts and JavaScript errors. Public download hashes/MIME/disposition are in publication/download-verification.json; public VM results and sanitized service receipts are in the same directory.

Loom testing is pending. No installation occurred on the development host; no GitHub release, push, recurring task or new release-management service was created.
