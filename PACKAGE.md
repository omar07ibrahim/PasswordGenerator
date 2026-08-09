# Password Policy State-Space

`password-policy-state-space` counts constrained visible-ASCII password spaces
exactly and exposes deterministic inspection, rank, and unrank operations. Its
production sampler selects one uniform integer rank with `secrets.randbelow`
and maps that rank to a candidate without retrying invalid strings.

The installed command can inspect a policy or measure each class minimum's
exact one-step marginal effect without sampling:

```bash
password-policy-lab inspect --length 20 --format json
password-policy-lab sensitivity --length 20 --format json
```

Sensitivity rows change one minimum at a time and are explicitly non-additive;
they do not estimate password strength.

`rank` and `unrank` are reversible and are intended only for explicitly public
test vectors. Both require `--acknowledge-reversible-output`; never use them
with a credential.

The wheel contains the typed Python package, server-rendered template and
stylesheet, and the `password-policy-lab` entry point. Repository-only tests,
portfolio evidence, and browser captures are deliberately excluded from the
installable distribution and remain available in the source repository.

No project license is currently declared. Public source availability alone
does not grant permission to copy, modify, or redistribute the package.
