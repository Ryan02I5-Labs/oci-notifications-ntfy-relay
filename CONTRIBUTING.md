# Contributing

Thanks for helping improve the relay. This project is maintained by one person,
so small, focused changes are the easiest to review.

## Reporting bugs and requesting features

- Open a [GitHub issue](https://github.com/Ryan02I5-Labs/oci-notifications-ntfy-relay/issues)
  for bugs and enhancement requests. Include the notification source (OCI Alarm,
  OSMH, Cloud Guard, HCP Terraform or Alertmanager), what you expected, and what
  ntfy showed. Remove topics, tokens and other private values from payloads.
- Report suspected vulnerabilities privately as described in
  [SECURITY.md](SECURITY.md), not in a public issue.

Issues and pull requests are the public record of discussion and decisions.

## Making a change

1. Fork the repository and create a branch from `main`.
2. Make one focused change per pull request.
3. Add or update tests (see [Testing policy](#testing-policy)) and update
   `README.md` when behavior, configuration or the message layout changes.
4. Open a pull request against `main` that says why the change is needed and
   what it changes.

A pull request is merged when:

- CI passes: unit tests, the container smoke test on `linux/amd64` and
  `linux/arm64`, and CodeQL analysis;
- automated code review has no unresolved findings;
- review conversations are resolved.

## Requirements for acceptable contributions

- Python 3.12, standard library first. A new dependency needs a reason in the
  pull request and must be pinned in `requirements.txt`.
- Follow the existing style in `func.py`: small functions, type hints, and a
  link to the upstream documentation for any payload field or API behavior the
  code relies on.
- Never log or return secret values (ntfy topic, tokens, access credentials);
  log only redacted text or booleans.
- GitHub Actions are pinned to full commit SHAs, and container base images to
  digests.

## Testing policy

Every new feature and every bug fix must add or update tests in
`test_func.py` that exercise the new behavior. Run them before opening a pull
request:

```bash
python3 -m unittest discover -s . -p 'test_func.py' -v
```

## Releases

Releases follow [Semantic Versioning](https://semver.org/) and are tagged
`vX.Y.Z`. Each GitHub Release has release notes that summarize user-visible
changes and name any security fix.
