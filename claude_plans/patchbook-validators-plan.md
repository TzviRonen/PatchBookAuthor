# PatchBook: record contributor names + per-verdict contributor sections

## Context

PatchBook (Jekyll site in `/workspace/patchbook`, hosted free on GitHub Pages) already has an automated validation pipeline: the "Validate" form opens a prefilled GitHub issue → `.github/workflows/validations.yml` runs `scripts/apply_validation.py` → the mark is appended to the post's `validations:` frontmatter → committed → `pages.yml` rebuilds and redeploys the site. So the "valid" counter already auto-increments and the host already auto-updates; **no backend server and no hosting changes are needed.**

What's missing: the contributor's name is not recorded (the form's name field was removed), and there is no contributors section at the bottom of posts. This plan adds both — covering **all three verdicts** (`valid`, `ai-slop`, `needs-fixing`), not just `valid`. The header counters for all three verdicts already exist and update automatically from frontmatter; no counter changes are needed beyond recording the marks.

Decisions made with the user:
- **Name source**: the GitHub username of the issue author (`github.event.issue.user.login`) — trusted from the event payload, not the spoofable issue body.
- **Rendering**: name is stored in `validations:` frontmatter; `post.html` renders a "Community review" section at the bottom with a contributor list per verdict (works unchanged with the preserve-on-republish logic in `/workspace/publish_to_patchbook.py`).
- **Dedupe**: one mark per (username, verdict) per post — a user may e.g. mark both `valid` and `needs-fixing`, but not the same verdict twice.

## Changes (all in `/workspace/patchbook`)

### 1. `.github/workflows/validations.yml`
Pass the issue author to the script in the "Apply validation" step:

```yaml
env:
  ISSUE_BODY: ${{ github.event.issue.body }}
  ISSUE_AUTHOR: ${{ github.event.issue.user.login }}
```

**Bug fix — trigger the Pages rebuild after the bot's push.** GitHub suppresses workflow runs for events created with the default `GITHUB_TOKEN` (recursion prevention), so the bot's `git push` does NOT fire `pages.yml`'s `on: push` — the site currently stays stale until the next human push. `workflow_dispatch` is the documented exception and `pages.yml` already declares it, so: add `actions: write` to the workflow's `permissions:` block and run `gh workflow run pages.yml` right after the successful `git push`. (See `patchbook/ARCHITECTURE.md` § "Gotcha".)

### 2. `scripts/apply_validation.py`
All of this is verdict-agnostic — it applies identically to `valid`, `ai-slop`, and `needs-fixing` marks (the script already accepts all three via the `VERDICTS` allowlist):
- Read `ISSUE_AUTHOR` from the environment (not from the hostile issue body). Sanitize with the existing `sanitize()` and validate against a GitHub-username allowlist regex (`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`); if absent/invalid, record the mark without a name (don't reject — keeps local/manual runs working).
- In `build_entry()`, add `    name: <username>` (via existing `yaml_str()`) to the entry lines.
- **Dedupe**: before inserting in `apply()`, parse the existing `validations:` block in the frontmatter (same simple line-based approach the file already uses) and exit with a distinct "already recorded" success path (exit 0, message `OK: already recorded`) if an entry with the same `name` + `verdict` exists. The same user can still record different verdicts on one post. The workflow's existing "no change applied" branch (`git diff --cached --quiet`) already handles the no-op commit case, so no workflow change needed for this.

### 3. `_layouts/post.html`
- Add a **Community review** section after the `<article class="prose">` body (bottom of the post): rendered only when `page.validations` is non-empty. It shows one contributor group per verdict, using the `valid_marks` / `slop_marks` / `fix_marks` lists already assigned at lines 11–13 (each group rendered only if its list is non-empty):

```
## Community review
Validated by:        ✓ alice · 2026-07-10    ✓ bob · 2026-07-09
Flagged AI-slop by:  ✗ carol · 2026-07-08
Needs fixing per:    ⚠ dave · 2026-07-07
```

- Reuse the existing badge colors for consistency (green/red/yellow, matching the header tally). Implement the three groups with a single Liquid include-style loop or a small repeated block — same markup, parameterized by list + label + badge class — rather than three copies of the rendering logic.
- For each mark with a `name`, link it to `https://github.com/<name>` (safe — name is workflow-validated against the username regex); marks without a name render as "anonymous". Show the date next to each name; show the mark's `note` if present.
- Keep the existing header tally (which already counts all three verdicts) and the "reader marks" list as-is.

### 4. No changes needed
- `assets/patchbook.js` / the form — the username comes from the issue author, so the client stays as-is.
- `publish_to_patchbook.py` — `_existing_validations()` copies the frontmatter block verbatim, so `name:` lines are preserved on republish automatically.
- Hosting/deploy — `pages.yml` already rebuilds on every push, including the bot's commits.

## Verification

1. Run the script locally against a copy of a post:
   `ISSUE_AUTHOR=testuser ISSUE_BODY=$'```yaml\ntype: validation\npost: _posts/<file>.md\nverdict: valid\nnote: test\n```' python scripts/apply_validation.py`
   — confirm the frontmatter gains `- verdict: valid / date / name: "testuser"`.
2. Run it a second time with the same author+verdict — confirm it exits with "already recorded" and the file is unchanged.
3. Repeat step 1 with `verdict: ai-slop` and `verdict: needs-fixing` (same and different authors) — confirm each records with the name, and that the same author with a *different* verdict is accepted while a repeat of the same verdict is deduped.
4. Run without `ISSUE_AUTHOR` — confirm the mark records without a name.
5. Build/preview the site locally (`serve.py` or `bundle exec jekyll build` if available) and check the post page: all three badge counts reflect the marks, the Community review section at the bottom shows the correct per-verdict groups with linked usernames (and omits empty groups), header reader-marks list intact.
5. Revert the test edits to the post before committing; end-to-end check happens on GitHub by opening a real validation issue after push.
