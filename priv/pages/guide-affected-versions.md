%{
  title: "Affected Versions",
  description: "What version facts a case records and how the published ranges are derived from them"
}
---

A case never stores version ranges. It stores **facts**: the commit that
introduced the vulnerability and the commit or commits that fixed it.
Everything version-shaped in the published record is derived from those
facts and the package's git repository. A release is affected exactly when
it contains an introducing commit and no fixing commit. A vulnerability
fixed and later reintroduced yields a second range; one without a released
fix yields an open-ended one.

Because everything is derived from them, the facts must be right:

- **The introducing commit is verified, never trusted.** It is the commit
  that added the vulnerable code (its parent must not contain it), not one
  that merely touched the file, and neither the reporter nor the advisory
  is authoritative about it.
- **The fix is where the vulnerability actually closes.** A follow-up
  correcting an incomplete first patch is the real boundary, and a fix
  backported to several branches has several SHAs; list them all.
- **Full 40-character commit SHAs, never tag SHAs.**

## What the Record Shows

Each affected package lists its distribution channels, prefilled by the
`otp` / `elixir` / `gleam` presets, and the derivation speaks each
channel's vocabulary: semver for a Hex package, OTP release and
per-application versions for OTP, plain commit SHAs for the source
repository. The CPE applicability ranges come out of the same derivation.

Most channels state each affected span as a bounded range, `from X before Y`.
OTP releases do not, because the version scheme only partially orders them: a
maintenance release like `27.3.4.15` and a `28.0` each carry changes the other
lacks, so no range can span the two. An OTP package with fixes on several
maintenance lines is published instead as one entry open from the introducing
release, carrying a transition per fix. A reader's version picks up the fixes
on its own line and no others.

## Deriving

Derivation runs when you press **Derive the case**, never on its own. The
result goes stale the moment a boundary fact, a channel, or the package
changes, and a stale or empty derivation renders as *no affected
versions*. The case flags stale packages and the **Publication** tab refuses
to publish over them; derive again after changing facts, and before trusting
the rendered record on the **CVE** tab.

If the derived ranges disagree with the advisory, a boundary commit is
wrong. Investigate before trusting either side.

## The Odd Cases

- **The fix is in no release yet.** The derivation reports it as pending and
  blocks publishing. Once the release is tagged, refresh the derivation to
  clear it; the cached result does not notice upstream changes on its own.
  When staying unreleased is intentional (a hotfix released from a
  maintenance branch and not merged back, leaving one of several fix commits
  outside every release), allow unreleased fixes on the package.
- **Vulnerable since the beginning of OTP's git history**: tick the OTP
  preset's since-creation checkbox. It stands for the erlang/otp root commit,
  and selects *unknown* for versions outside the derived ranges (below). When
  the flaw is older than the import too, give that boundary the version `0`:
  the range then starts at `0`, on the release channel and on the
  application's.
- **Unsure whether releases older than the introducing commit are safe?** Set
  the package's *versions outside the derived ranges* to **unknown** — for a
  repository whose history starts at a squashed import, or when nobody audited
  that far back. The record then claims nothing about them
  (`defaultStatus: unknown`), and the CPE range drops its lower bound, treating
  the older era as possibly affected. The default, **unaffected**, asserts
  every release outside the derived ranges is known safe. The OTP preset
  selects unknown for a root-commit intro; it is an ordinary setting from there
  on.
- **No usable repository**: it is gone, or its tags are unreliable or
  incomplete. Enter explicit version boundaries instead of commits.
- **Prereleases** count as releases unless the project opts out, as OTP
  does.
- **A hosted service** has no versions; its channel carries date boundaries
  directly, and those are published verbatim.
