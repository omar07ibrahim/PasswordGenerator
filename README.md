# Password Policy State-Space Lab

This repository is being rebuilt around an exact security-engineering core for
constrained password policies. Instead of forcing required characters into a
string and shuffling, the core counts the complete valid state space, assigns
every valid password one stable rank, and samples one rank uniformly with
Python's `secrets` module.

The original Flask route is still present in this first foundation slice and
is **not yet connected to the audited sampler**. Do not treat the legacy web
form as the secure interface; its replacement belongs to the next reviewable
change.

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

## Development gate

The package has no runtime dependencies and supports Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

The current gate runs Ruff, strict mypy, exhaustive small-space oracle tests,
and combined line/branch coverage.
