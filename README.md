# Password Policy State-Space Lab

Exact combinatorics and one application-level uniform-rank selection for
constrained password policies. Instead of assembling required characters and
shuffling—or retrying until a candidate happens to pass—the lab counts the
complete valid state space, assigns every member one stable rank, and samples
that rank uniformly.

![Real server-side validation run](docs/assets/web-validation-demo.gif)

> This is a real loopback Waitress session, not a mockup. The capture visits the
> live GET page, submits an invalid length to the real Flask handler, and records
> its `400` response. A process-local guard makes the evidence build fail if the
> sampler is called, so no password is generated or placed in repository media.

## What makes the core auditable

| Guarantee | Mechanism | Review surface |
|---|---|---|
| Exact policy cardinality | bounded bottom-up dynamic programming with arbitrary-precision integers | CLI JSON/CSV and the web audit panel |
| Uniform sampling | exactly one `secrets.randbelow(total)` followed by deterministic `unrank` | source-derived sampling diagram and rank-selection call tests |
| Complete reversible ordering | tested `rank`/`unrank` bijection over every valid string | exhaustive small-space Cartesian oracles |
| Bounded failure | malformed, impossible, or excessive policies fail before enumeration | policy, request, and budget tests |
| Reproducible evidence | deterministic raw outputs, source hashes, browser assertions, and artifact digests | `docs/evidence/manifest.json` |

Ranks are deterministic inspection tools, not credentials to reuse. A rank is a
reversible encoding of its candidate under one exact ordered policy.

## Setup and verify

![Setup, verification, and local-run workflow](docs/assets/setup-workflow.svg)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

The package supports Python 3.11 or newer. `make check` runs Ruff, formatting,
strict mypy, exhaustive and independent mathematical oracles, real Flask
request tests, 100% combined line/branch coverage, and the committed-evidence
integrity check.

Start the pinned production WSGI server on loopback:

```bash
waitress-serve \
  --host 127.0.0.1 \
  --port 5000 \
  --max-request-body-size=1024 \
  --max-request-header-size=16384 \
  --channel-timeout=30 \
  --call password_policy_lab.web:create_app
```

Then open `http://127.0.0.1:5000`.

## Architecture

![Source-derived package architecture](docs/assets/architecture.svg)

The browser and CLI share the same versioned visible-ASCII policy, exact
`PasswordSpace`, and inspection model. The web route constructs one space,
derives the displayed metrics from that same object, and then performs one
sample. Invalid requests stop before policy construction. The CLI inspection
path is deterministic and consumes no entropy.

![AST-verified uniform sampling flow](docs/assets/uniform-sampling-flow.svg)

The sampling diagram is checked against the current syntax tree: the production
path selects an integer with `secrets.randbelow(total)` and passes it directly
to `unrank`. Project code has no modulo reduction, candidate-rejection loop, or
use of the `random` module. (`secrets.randbelow` may perform its own internal
random-bit rejection sampling.)

## Exact state-space evidence

![Exact policy state space across lengths 8 through 32](docs/assets/state-space-sweep.png)

The figure is rendered from the committed
[`state-space-sweep.csv`](docs/evidence/state-space-sweep.csv), produced by the
real CLI for lengths 8–32. It pairs exact entropy bounds with the
policy-satisfying share on an honest 0–100% scale. Counts and entropy describe a
uniform draw from this state space; they are not a password-strength score or an
authentication guarantee.

## Deterministic audit CLI

The inspection commands never sample a password. They emit exact decimal
integers, a reduced satisfying fraction, rank interval, integer entropy bounds,
bounded-DP limits, and a SHA-256 fingerprint of the complete ordered policy.
Arbitrary-size JSON values remain strings so JavaScript readers cannot silently
round them.

![Real deterministic CLI inspection](docs/assets/cli-inspect.png)

```bash
password-policy-lab inspect --length 20 --format json
password-policy-lab sweep \
  --start-length 8 \
  --end-length 32 \
  --format csv
```

The raw, machine-reviewable counterpart is
[`cli-inspect.txt`](docs/evidence/cli-inspect.txt). Outputs contain no
timestamps, machine paths, locale-dependent formatting, or randomness.

`rank` and `unrank` exist only for public deterministic test vectors. Both
require `--acknowledge-reversible-output`; `rank` accepts its candidate only
through bounded standard input or hidden terminal input, never an argument.
Do not use either command with a credential.

## Local web interface

<table>
  <tr>
    <td width="67%">
      <img src="docs/assets/web-home.png" alt="Real desktop GET response from the local policy lab">
    </td>
    <td width="33%">
      <img src="docs/assets/web-home-mobile.png" alt="Real mobile-width GET response from the local policy lab">
    </td>
  </tr>
  <tr>
    <td><strong>Desktop:</strong> exact metrics and uniform-sampler workflow.</td>
    <td><strong>Mobile:</strong> the same semantic flow without horizontal overflow.</td>
  </tr>
</table>

![Real rejected request with audit metrics withheld](docs/assets/web-invalid-length.png)

The form accepts lengths from 8 through 128. Every generated value satisfies
the fixed lowercase, uppercase, digit, and ASCII-punctuation minima. The
interface is entirely server-rendered: one package-local stylesheet, no
JavaScript, CDN, web font, external request, cookie, session, or storage.

The documented Waitress command binds only to loopback; the Flask application
trusts only loopback host names. With that command, Flask and Waitress both
enforce the 1 KiB request-body boundary. Responses are non-cacheable and carry
a restrictive CSP, origin isolation, frame denial, no-referrer, and
MIME-sniffing protections. The current endpoint has no server-side mutation,
session, or authenticated identity, so it has no CSRF token; adding any of
those features requires revisiting that decision.

The server does not log or retain a generated value, but Python, the browser,
and the clipboard cannot promise memory zeroization. Run the app as an
unprivileged user, and do not change the bind address without transport
security and a deliberate deployment boundary.

These choices follow the official
[Flask security guidance](https://flask.palletsprojects.com/en/stable/web-security/)
and
[deployment guidance](https://flask.palletsprojects.com/en/stable/deploying/).

## Rebuild the evidence

Install the pinned Chromium build into the ignored repository-local directory,
then regenerate every raw and visual artifact:

```bash
make evidence-browser
make evidence
make evidence-check
```

`make evidence` keeps browser binaries, profiles, Matplotlib state, caches, and
temporary files under this repository. On a minimal Linux image, Chromium's OS
runtime libraries still need to be supplied by that environment; the target
never invokes a privileged system-package install.

![Real project quality gate](docs/assets/quality-gate.png)

Evidence provenance stays next to the visuals:

- [`manifest.json`](docs/evidence/manifest.json) — source and artifact SHA-256
  digests, dimensions, tool versions, HTTP statuses, DOM assertions, and the
  zero-sampler-call guard result;
- [`web-validation-reference.png`](docs/evidence/web-validation-reference.png)
  — the three lossless, full-resolution browser frames used to independently
  verify every decoded GIF frame;
- [`quality-gate.txt`](docs/evidence/quality-gate.txt) — normalized output from
  the real Ruff, format, mypy, pytest, coverage, and dependency checks;
- [`state-space-sweep.csv`](docs/evidence/state-space-sweep.csv) — exact plot
  input from the public CLI;
- [`cli-inspect.txt`](docs/evidence/cli-inspect.txt) — exact deterministic
  inspection output.

No timestamp or absolute machine path is accepted into the manifest or raw
evidence. `make evidence-check` recomputes hashes and semantic invariants so a
code change cannot silently leave stale portfolio media behind.
