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

## Deriving

Derivation runs when you press **Derive the case**, never on its own. The
result goes stale the moment a boundary fact, a channel, or the package
changes, and a stale or empty derivation renders as *no affected
versions*. The case flags stale packages and the preview refuses to publish
over them; derive again after changing facts, and before trusting any
preview.

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
  and the record reports the pre-R13B03 era as unknown.
- **No usable repository**: it is gone, or its tags are unreliable or
  incomplete. Enter explicit version boundaries instead of commits.
- **Prereleases** count as releases unless the project opts out, as OTP
  does.
- **A hosted service** has no versions; its channel carries date boundaries
  directly, and those are published verbatim.
