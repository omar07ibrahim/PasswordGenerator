# Password Policy State-Space Lab

This repository is being rebuilt around an exact security-engineering core for
constrained password policies. Instead of forcing required characters into a
string and shuffling, the core counts the complete valid state space, assigns
every valid password one stable rank, and samples one rank uniformly with
Python's `secrets` module.

The package also exposes a deliberately small local Flask interface. It accepts
one bounded length, constructs the fixed four-class policy, and routes
generation through the same audited sampler.

## Core guarantees

- character classes are ordered, nonempty, disjoint visible-ASCII sets;
- each class can declare an exact minimum count;
- malformed, impossible, or computationally excessive policies fail before
  state enumeration;
- dynamic programming returns the exact integer number of valid passwords;
- `rank` and `unrank` form a tested bijection over that complete space;
- production sampling makes one `secrets.randbelow(total)` call and never uses
  retry-until-valid generation, modulo reduction, or `random`.

Ranks are deterministic inspection tools, not passwords to reuse or an
authentication primitive. The ordering depends on the exact policy and symbol
order.

## Deterministic audit CLI

The CLI never samples a password. It inspects the fixed visible-ASCII profile,
emits exact state-space integers, and produces stable machine-readable data for
review and plotting:

```bash
password-policy-lab inspect --length 20 --format json
password-policy-lab sweep \
  --start-length 8 \
  --end-length 32 \
  --format csv
```

`inspect` reports valid, unconstrained, and excluded counts; an exact reduced
satisfying fraction; exact floor/ceiling bounds on `log2(valid)`; the rank
interval; bounded-DP upper bounds; and a SHA-256 fingerprint of the complete
ordered policy. Arbitrary-size integers are decimal strings in JSON so
JavaScript readers cannot silently round them. Outputs contain no timestamps,
machine paths, locale formatting, or randomness.

`rank` and `unrank` exist only for public deterministic test vectors. A rank is
a reversible encoding of its candidate under the fingerprinted policy, so rank
output is secret-equivalent. Both commands require
`--acknowledge-reversible-output`; `rank` accepts the candidate only through
hidden terminal input or bounded standard input, never an argument. Do not use
either command with a credential:

```bash
password-policy-lab unrank \
  --length 8 \
  --rank 0 \
  --acknowledge-reversible-output \
  --format json
```

The entropy bounds describe a uniform draw from the counted state space. They
are not a password-strength score and say nothing about a human-chosen value or
an online authentication system.

## Local web interface

Install the project, start its pinned WSGI server on loopback, and open
`http://127.0.0.1:5000`:

```bash
waitress-serve \
  --host 127.0.0.1 \
  --port 5000 \
  --max-request-body-size=1024 \
  --max-request-header-size=16384 \
  --channel-timeout=30 \
  --call password_policy_lab.web:create_app
```

The form accepts lengths from 8 through 128. Every generated password contains
at least one lowercase letter, uppercase letter, digit, and ASCII punctuation
symbol. The application binds only to loopback, trusts only loopback host
names, keeps no session or storage, loads no external assets, and marks every
application response as non-cacheable. Run it as an unprivileged user and do
not change the bind address unless you also add transport security and an
appropriate deployment boundary.

The request-body bound is enforced by both Waitress and Flask. The current form
has no account, cookie, session, persistent state, or server-side mutation, so
it has no CSRF token. Adding any of those features requires revisiting that
decision. The application does not log or retain generated values, but Python,
the browser, and the clipboard cannot promise memory zeroization.

These choices follow the official
[Flask security guidance](https://flask.palletsprojects.com/en/stable/web-security/)
and
[deployment guidance](https://flask.palletsprojects.com/en/stable/deploying/).

## Development gate

The package supports Python 3.11 or newer and pins its small web runtime.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

The gate runs Ruff, strict mypy, exhaustive small-space oracle tests, real Flask
request tests, and combined 100% line/branch coverage.
