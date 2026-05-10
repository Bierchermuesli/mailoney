# Pull-request drafts

Paste-ready descriptions for the five upstream PRs this fork has been
preparing against `phin3has/mailoney`. One file per branch; each is
self-contained and can be opened independently.

Suggested order (least to most contentious, smallest to largest):

1. [`feat/smtp-dual-stack`](01-smtp-dual-stack.md) — IPv6 bind fix
2. [`feat/db-optional`](02-db-optional.md) — DB-optional mode + structured logging
3. [`feat/prometheus-metrics`](03-prometheus-metrics.md) — `/metrics` endpoint + Grafana dashboard
4. [`feat/data-handling`](04-data-handling.md) — SMTP DATA phase + body storage (supersedes upstream PR #29)
5. [`feat/starttls`](05-starttls.md) — STARTTLS support

## Opening them

For each:

```bash
gh pr create \
  --repo phin3has/mailoney \
  --base main \
  --head Bierchermuesli:<branch> \
  --title "<title from .md>" \
  --body-file pull-requests/<file>.md
```

Or via the GitHub UI — the file content is the PR body.
