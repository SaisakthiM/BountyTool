# BountyTool

End-to-end bug bounty reconnaissance, vulnerability triage and reporting, in one
binary with a CLI and a full-screen TUI.

Give it a domain you are authorised to test. It enumerates subdomains, resolves
and probes them, fingerprints what is running, crawls for endpoints, harvests
parameters, runs template scanning and its own native vulnerability probes,
deduplicates and scores everything, and writes a report you can hand to a program
triager.

```
scope ─▶ passive ─▶ dns ─▶ probe ─▶ fingerprint ─▶ [ports] ─▶ [urls ─▶ content ─▶ params]
      ─▶ nuclei ─▶ active probes ─▶ triage ─▶ report (.md / .json / .html)
```

Square brackets are profile-dependent: `light` skips them, `standard` includes
crawling and discovery, `deep` adds port scanning.

## Safety model

This tool sends real traffic. It is built so that it cannot quietly test
something you did not declare:

- **Authorization gate.** No active stage runs without `-y`/`--i-have-authorization`.
- **Explicit scope.** Every network call funnels through one `Scope::allows`
  check. Undeclared hosts, `exclude` entries, `.gov`/`.mil` domains and private
  addresses are refused. Loopback and RFC1918 targets need
  `allow_private_ips = true` in the scope file, which is off by default.
- **Rate limiting.** A global token bucket plus a hard per-host request budget.
- **Bounded work.** Every stage caps how many hosts, URLs, parameters and
  requests it will touch.
- **Dry runs are inert.** `--dry-run` prints what each stage would do without
  opening a socket or creating a session.
- **Detection, not exploitation.** The SQL injection probe looks for error,
  boolean and time-based signals; it never dumps data. `sqlmap` is only run when
  you enable it, with `--level=1 --risk=1`.

You are responsible for staying inside the program's rules.

## Install

### Arch Linux (AUR)

```bash
yay -S bountytool
```

### From source

```bash
git clone https://github.com/saisakthi/bountytool
cd bountytool
make            # release build -> target/release/bountytool
sudo make install
```

`make install` puts the binary in `/usr/local/bin`, the man page in
`/usr/local/share/man/man1` and the docs in `/usr/local/share/doc/bountytool`.
Override with `PREFIX`, `BINDIR`, `DESTDIR` as usual.

## External tools

The engine is hybrid: it orchestrates the best external scanners and adds its
own native probes on top. Core scanners are required; everything else is
optional and each stage degrades gracefully without it.

```bash
bountytool doctor                      # what is installed, what is missing
sudo bountytool doctor --install       # install the core set with pacman + yay
bountytool doctor --install --group recommended
./scripts/install-deps.sh              # same thing, before the binary exists
```

| Tool | Stage | Package |
| --- | --- | --- |
| nuclei | template scanning (**required**) | `aur/nuclei` |
| subfinder | passive subdomains (**required**) | `aur/subfinder` |
| httpx | HTTP probing (**required**) | `aur/httpx` |
| katana | crawling | `aur/katana-bin` |
| ffuf | content discovery | `aur/ffuf-bin` |
| gobuster | content discovery fallback | `extra/gobuster` |
| dalfox | XSS verification | `aur/dalfox` |
| sqlmap | SQLi confirmation | `extra/sqlmap` |
| nmap / naabu | port scanning (deep) | `extra/nmap`, `aur/naabu` |
| findomain | extra passive sources | `extra/findomain` |
| interactsh-client | out-of-band callbacks | `aur/interactsh-client` |
| seclists | wordlists | `aur/seclists` |

Without any external tool the native prober, crawler, form harvester and probes
still run, so a scan produces results on a bare machine.

## Quick start

```bash
# 1. declare scope
cp scope.example.toml scope.toml && $EDITOR scope.toml

# 2. check the toolchain
bountytool doctor

# 3. scan
bountytool example.com -y                     # CLI progress
bountytool example.com -y --tui               # live dashboard
bountytool example.com -y --profile deep      # add ports, more probes
bountytool example.com -y --dry-run           # show what would run
```

Target can be given positionally or through the scope file; `./scope.toml` is
picked up automatically.

## CLI

```
bountytool [TARGET] [OPTIONS]
bountytool tui    [TARGET] [OPTIONS]
bountytool doctor  [--install] [--group core|recommended|heavy] [--dry-run] [--strict]
bountytool sessions [--limit N] [--json]
bountytool config  [--init] [--force] [--file FILE]
```

| Option | Meaning |
| --- | --- |
| `-p, --profile light\|standard\|deep` | scan depth (default `standard`) |
| `--scope FILE` | scope file to use |
| `--in-scope HOST` | add an in-scope host (repeatable) |
| `-y, --i-have-authorization` | required for active scanning |
| `--tui` | run inside the TUI |
| `--dry-run` | plan the scan: no traffic sent, no session created |
| `--only STAGE[,STAGE]` | run only these stages |
| `--skip STAGE[,STAGE]` | skip these stages |
| `-f, --format md,json,html` | report formats (default all three) |
| `--resume DIR` | continue a session, skipping completed stages |
| `--open` | open the HTML report when finished |
| `--quiet` / `-v` | result only / include debug logs |
| `--config FILE` | configuration file to use |

Stages: `scope`, `passive`, `dns`, `probe`, `fingerprint`, `ports`, `urls`,
`content`, `params`, `nuclei`, `active`, `triage`, `report`.

Exit codes: `0` success, `1` generic failure, `2` missing required tool,
`3` scope or authorization refusal, `4` configuration error, `130` interrupted.

## TUI

`bountytool example.com -y --tui`

| Key | Action |
| --- | --- |
| `tab` / `→`, `shift+tab` / `←` | switch tab (overview, findings, hosts, log) |
| `↑`/`↓` or `k`/`j` | scroll |
| `pgup`/`pgdn`, `g`/`G` | page, jump to top/bottom |
| `q` / `esc` / `ctrl+c` | cancel the scan and quit |

The TUI drains the same event bus as the CLI, so both frontends always show the
same scan.

## What gets probed natively

| Probe | Signal |
| --- | --- |
| SQL injection | database error strings, boolean differentials, time delays |
| SSRF | response differentials on URL-accepting parameters, OAST callbacks |
| Open redirect | `Location` pointing at injected infrastructure |
| CORS | reflected origin, wildcard with credentials, `null` origin |
| CRLF injection | injected header reflected into the response |
| Path traversal | traversal payloads that return file content |
| SSTI | arithmetic template payloads evaluated in the response |
| XSS | unencoded reflection of a unique marker |

Findings carry evidence: request, response snippet, and a ready-to-run `curl`
command.

## Triage

Every finding gets a dedupe key of `category|host|endpoint|parameter|payload
class`, then a score of *severity × confidence × reachability*. Findings at or
above `1.5` are primary findings; the rest stay in an observations appendix
instead of being thrown away. Nothing is reported twice.

## Reports

Written into the session directory:

- `report.md` — the readable write-up: scope, at-a-glance counts, findings with
  evidence and remediation, attack surface, tooling, degraded coverage.
- `report.json` — versioned (`schema: 1`) machine-readable output.
- `report.html` — a single self-contained file you can open or attach.

## Sessions

Each scan owns a directory under `~/.local/share/bountytool/sessions/`:

```
20261108-101500-example-com/
├── session.json      manifest: profile, scope, stage timings, tools, degraded notes
├── artifacts/        scope.json, hosts.jsonl, urls.txt, params.jsonl, findings.jsonl, …
├── raw/              unmodified scanner output
└── report.md|json|html
```

Stage records double as a resume cache: `--resume <dir>` skips stages that
already completed. `bountytool sessions` lists them.

## Configuration

Defaults are compiled in; `~/.config/bountytool/config.toml` overrides them key
by key, and `BOUNTYTOOL_*` environment variables win over the file.

```bash
bountytool config          # print the merged configuration
bountytool config --init   # write a starter file
```

Keys: `concurrency`, `rate_limit`, `per_host_budget`, `http_timeout_secs`,
`tool_timeout_secs`, `max_runtime_secs`, `user_agent`, `nuclei_severity`,
`nuclei_rate_limit`, `katana_depth`, `probe_params_limit`, `oast`,
`sqlmap_verify`, `seclists_dir`, `wordlist`, `output_dir`.

Environment overrides: `BOUNTYTOOL_CONCURRENCY`, `BOUNTYTOOL_RATE_LIMIT`,
`BOUNTYTOOL_PER_HOST_BUDGET`, `BOUNTYTOOL_TIMEOUT`, `BOUNTYTOOL_USER_AGENT`,
`BOUNTYTOOL_SECLISTS`, `BOUNTYTOOL_WORDLIST`, `BOUNTYTOOL_OUTPUT`,
`BOUNTYTOOL_NUCLEI_SEVERITY`, `BOUNTYTOOL_OAST`, `BOUNTYTOOL_SQLMAP`,
`BOUNTYTOOL_DATA_DIR`.

## Development

```bash
make            # release build
make debug      # fast build
make check      # type-check everything
make clippy     # lints, warnings are errors
make test       # test suite
make install    # PREFIX=/usr DESTDIR=… supported
make dist       # source tarball for the AUR
make aur        # regenerate .SRCINFO
```

Layout:

```
src/
├── main.rs        dispatch, CLI renderer, exit codes
├── cli.rs         clap definitions and argument resolution
├── tui/           ratatui frontend over the event bus
├── pipeline/      the stages, one module each
├── probes/        native vulnerability probes
├── tools/         registry, process runner, output parsers
├── findings/      model, dedupe, scoring
├── report/        markdown, json, html
├── scope.rs       scope and authorization gate
├── session.rs     session persistence
├── config.rs      layered configuration
├── doctor.rs      toolchain inspection and installation
└── events.rs      the frontend-agnostic event bus
```

The engine never prints. `pipeline::run` emits `ScanEvent`s; the CLI turns them
into an `indicatif` spinner, the TUI into widget state. That is why both
frontends behave identically.

### Publishing to the AUR

1. Bump `version` in `Cargo.toml` and `pkgver` in `PKGBUILD`.
2. Tag the release: `git tag v0.1.0 && git push --tags`.
3. `make aur`, then push `PKGBUILD` and `.SRCINFO` to the `bountytool` AUR repo.

## Limitations

- Detections are heuristics. A finding is a lead to verify by hand, not proof.
- Blind SSRF and blind injection need `oast = true` and a working
  `interactsh-client`.
- JavaScript-rendered endpoints are invisible to the crawler.
- Stealth is not a goal: scanning is rate limited but not obfuscated.

## License

MIT. See [LICENSE](LICENSE).
