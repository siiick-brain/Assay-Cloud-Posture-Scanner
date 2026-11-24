# Writing style

These rules apply to code comments, docstrings, docs and commit messages. scripts/check-style.ps1 checks the mechanical ones and the commit-msg hook checks commits.

## Comments and docstrings
- Comments explain why. Delete any comment that restates the next line.
- One short line per comment. No banners, dividers, numbered steps or emoji.
- Docstrings only on public modules and functions. One plain line unless the behavior surprises.
- No TODO or FIXME in merged code.

## Prose
- Direct and specific. Vary sentence length.
- No em dashes.
- No comma before "and" or "or" in a list of three or more.
- Banned words and phrases: robust, seamless, leverage, comprehensive, delve, crucial, ensure that, it is important to note, in order to, furthermore, moreover, this function is responsible for, utilize. The full list lives in scripts/style-banned.txt.
- Frameworks are "informed by". Never claim compliance or certification.

## Commits
- Imperative title under 72 characters, no trailing period.
- No body unless needed. No trailers.
- Author must match .githooks/author.txt.
