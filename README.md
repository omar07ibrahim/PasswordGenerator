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
