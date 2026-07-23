<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

---
name: find-intro-commit
description: Find the git commit that introduced a vulnerability. Use when filing a CVE and the introducing commit SHA is unknown or unverified.
---

# CVE Introducing Commit Finder

**This skill has one job: return a SHA.** Varsel derives the affected version range from the introducing commit you give it, so the SHA must be the real introducing commit — not a tag SHA, not a guess. Do not discuss the vulnerability, do not sanity-check the advisory, do not ask questions. Clone the repo, do the git archaeology, report the commit. If genuinely stuck, report what you found and why it is inconclusive — still no discussion.

## When to use

Only run this skill if the introducing commit is **not already known**. If a start version/tag was provided as a hint, treat it as a starting point for investigation, not ground truth.

## Process

### 1. Identify the repository and vulnerable code

From the case (or task description), determine:
- The GitHub repository
- The affected files and functions (from the affected-package program files)
- The fix commit SHA (upper bound, if known)
- Any hint about the introducing version (treat as approximate)

### 2. Clone the repository (if not already present)

```bash
git clone https://github.com/<owner>/<repo>.git /tmp/<repo>
cd /tmp/<repo>
```

If already cloned: `cd /tmp/<repo> && git fetch`.

### 3. Locate the fix commit in history

```bash
git show <fix-sha> -- <programFile>
```

Understand the fix so you know what the vulnerable pattern looks like.

### 4. Search for when the vulnerable code was introduced

Use `git log` with `-S` (pickaxe) or `-G` (regex):

```bash
git log --oneline -S '<distinctive-code-fragment>' -- <programFile>
git log --oneline -G '<pattern>' -- <programFile>
git log --oneline <fix-sha> -S '<fragment>' -- <programFile>
```

**Follow renames.** If the result looks like a refactor (a "move"/"split"/"extract" commit, or a date that postdates known affected releases), the vulnerable code likely lived at an earlier path:

```bash
git log --oneline --follow -S '<fragment>' -- <programFile>
git log --oneline -S '<fragment>'          # or drop the path entirely
```

### 5. If a hint version was provided

```bash
git show <hint-tag>:<programFile> | grep -n '<pattern>'
git log --oneline <hint-tag> -S '<fragment>' -- <programFile>
```

### 6. Use `git bisect` for complex cases

When pickaxe search is inconclusive (the vulnerability is in logic, not a specific string):

```bash
git bisect start
git bisect bad <fix-sha>
git bisect good <known-safe-tag-or-sha>
# test each commit, mark git bisect bad / git bisect good
git bisect reset
```

### 7. Verify the introducing commit

```bash
git show <candidate-sha> -- <programFile>
git show <candidate-sha>~1:<programFile> | grep -n '<pattern>'   # parent must NOT be vulnerable
git rev-parse <tag>^{}                                            # commit SHA for a tag, if needed
```

Confirm:
- The vulnerable code was **added** (not just touched) in this commit.
- The commit **before** it does not contain the vulnerability.
- The SHA is a real commit, not a tag SHA.

## Output

Return exactly:
- The introducing commit SHA (40-char)
- The commit message and date (one line)
- Confidence: **high** / **medium** / **low**

Nothing else. Whoever is running `/new-cve` submits this SHA as the `introduced_commit` (preset) or introducing `version_event` on the case; Varsel derives the version range and it gets eyeballed there via `render_case_preview` — you do not reconcile the range yourself.