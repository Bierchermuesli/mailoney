# Pull-request drafts

Paste-ready descriptions for the five upstream PRs this fork has been
preparing against `phin3has/mailoney`. One file per branch; each
stands alone and can be opened independently — the maintainer can
land any subset in any order.

## Suggested order

Revised from "smallest to largest" to "maximize maintainer goodwill
along the way." Upstream activity is low (PR #29 sat ~7 weeks before
a first response), so the cadence matters more than strict size
ordering.

| # | Branch | File | Why this slot |
|---|---|---|---|
| 1 | `feat/smtp-dual-stack` | [01-smtp-dual-stack.md](01-smtp-dual-stack.md) | Smallest, pure bug fix. Establishes a clean first interaction. |
| 2 | `feat/data-handling` | [02-data-handling.md](02-data-handling.md) | Engages with the maintainer's existing review thread on PR #29. Answers all three open questions directly. Shows due diligence. |
| 3 | `feat/starttls` | [03-starttls.md](03-starttls.md) | Pure addition + completes an EHLO capability the upstream already advertises but doesn't implement. Small bonus EHLO-format bug fix. |
| 4 | `feat/prometheus-metrics` | [04-prometheus-metrics.md](04-prometheus-metrics.md) | Strictly additive (opt-in via env var). Includes the Grafana dashboard so reviewer sees concrete value. |
| 5 | `feat/db-optional` | [05-db-optional.md](05-db-optional.md) | Biggest design change. Six commits, touches default behaviour. Save for last when there's merge credibility to spend on it. |

## Cadence advice

Don't open all at once. Two reasons:

1. **Five PRs landing on the same day reads as a takeover**, especially
   on a low-activity project. Same five PRs spread over a couple of
   months reads as an engaged contributor.
2. **Maintainer response time is itself signal.** If PR #1 sits for
   weeks, opening four more on top of it won't make them happen
   faster — and you've used up the goodwill of the easy PRs without
   getting feedback on the harder ones.

Suggested pace: open the next PR only after the previous one has
either landed or received a substantive review comment.

## Optional first step: a meta-issue

For a low-activity upstream, a *single issue* listing the planned
contributions can be cheaper than five PR descriptions. Title:

> Proposed contributions — feedback wanted before opening PRs

Body: one bullet per branch, two lines each, link to your fork's
branch. Ask: "Which of these would you accept as a PR? Anything
you'd rather not have?" Lets the maintainer say no early to the
contentious changes, signals respect for their time, and converts
some of the PR-review effort into lower-stakes issue discussion.

## Opening them

```bash
gh pr create \
  --repo phin3has/mailoney \
  --base main \
  --head Bierchermuesli:<branch> \
  --title "<title from .md>" \
  --body-file pull-requests/<NN-name>.md
```

Or via the GitHub UI — the file content is the PR body.

## Inter-PR conflicts

All four remaining branches touch `mailoney/core.py` (mostly
`_handle_client` and `SMTPHoneypot.__init__`). Whatever lands second
onwards will need a small rebase against the new `main`. The
conflicts are mechanical — different lines in the same elif chain,
additional `__init__` params — typically a few minutes per PR.

If you find the rebase produces unexpected conflicts, that's also
signal: it means upstream has been active during the gap. Useful to
know before opening the next PR.
