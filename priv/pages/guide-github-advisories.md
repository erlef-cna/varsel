%{
  title: "GitHub Advisories",
  description: "Linking a case to its GitHub security advisory, keeping the two in sync, and reporting a case to maintainers on GitHub"
}
---

A case and a GitHub security advisory describe the same vulnerability. The
case's **GitHub** tab connects them. It compares the two field by field,
carries fields across, reports a case to the maintainers, and shows who has
access on either side. The [Maintainer Process](/maintainer-process)
describes the same integration from the maintainer's side.

## What Your Account Needs

The tab works through the EEF CNA app on the advisory's repository. Who can
act depends on the role:

- **Supporters and everyone else on the case** act with their own GitHub
  account. The app must be installed on the repository, and the account must
  have access to the repository on GitHub. Link a GitHub account in
  [account settings](/settings/account){rel=nofollow} if yours has none. The settings page
  also shows where the app can act for you.
- **Points of Contact** act through the app when their own account cannot,
  and with the GitHub CLI where the app is not installed. See
  [the last section](#points-of-contact-acting-without-access).

When you cannot act, the tab says why and holds Refresh, Push, and Report. A
repository without the app needs its owner to install it.

## Cases That Start from an Advisory

- **You have the advisory.** On [Cases](/cases){rel=nofollow}, open a case from the
  advisory's URL or GHSA id. The case arrives filled in from the advisory and
  linked to it.
- **A maintainer submitted it.** A maintainer whose repository has the app
  installed submits their advisory on the [report form](/report){rel=nofollow}. The case
  holds no report, only the advisory's title and the link, and the maintainer
  is on it. The advisory is the claim you triage. Pull its fields once you
  accept the case.
- **A report names it.** A report can name an advisory as `github_advisory`
  beside its text, without a link. Link it once you accept the case, but read
  the warning below first.

:::warning
**Check the reporter's access on GitHub before you link an advisory a report names.** Everyone on a case reads its linked advisory and the advisory's comments, and the reporter is on the case. Knowing an advisory's address does not give access to it. Link the advisory only when the reporter already has access on GitHub, for example as a collaborator.
:::

## Linking and Comparing

Link an advisory by its URL or GHSA id. The tab then compares the case with
the advisory, field by field: title, each `###` section of the description,
CVE ID, CVSS vector, CWEs, credits, and the derived ranges of each channel,
spelled the way GitHub spells them. Description content outside these
sections shows as a warning and is never pulled.

- **Pull** a field when the advisory is right. A pull adds and replaces
  values on the case and never removes one.
- **Push** a field when the case is right. A push writes to the advisory as
  you, so GitHub decides whether you may.
- **Refresh** reads the advisory again after it changed on GitHub.

The linked advisory is the first reference of the published record, tagged
as the vendor advisory, so the case stores no reference for it. Unlink
removes it. Linking, pulling, and unlinking are edits to the case: after
approval, only a Point of Contact can do them.

## Reporting to the Maintainers

A case without an advisory can be reported to the maintainers of one of its
GitHub repositories. The tab sends a private vulnerability report in your
name, with everything the case states and a description you write for the
maintainers. The advisory GitHub opens for the report becomes the linked
one. GitHub takes no credits on a private report, so push them to the
advisory afterwards.

- A repository that takes no private reports is flagged. Point its
  maintainers to the [Maintainer Process](/maintainer-process), which tells
  them how to turn reporting on.
- GitHub takes no report from an administrator of the repository. Where you
  are one, the tab opens a draft advisory in your name instead.

## People

The tab shows who has access on either side, one row per person. On the
case, that is an assignment or an invite. On GitHub, it is a collaborator, a
member of a collaborating team, or an owner of the organization.

- **On GitHub only:** give the person access to the case with one click, as
  an assignment or an invite. The invite email goes to the address GitHub
  lists for them. A person without one is invited without an email, since
  they already see the advisory.
- **On the case only:** a Point of Contact adds the person to the advisory's
  collaborators with one click. GitHub gives a collaborator write access to
  the advisory. This needs a GitHub account linked to the person's account
  here.

## Comments

While a case is open, it reads the comments of its linked advisory every five
minutes and shows them in its own discussion. GitHub does not serve
confidential comments, so the advisory may hold more than the case shows.

A comment written on the case can be posted on the advisory as well. It posts
as you where your GitHub login can write there, and otherwise as the EEF CNA
app, naming you. A mention carries the person's name to the advisory, and
mentions nobody on GitHub.

## Points of Contact: Acting Without Access

A Point of Contact acts through the app when their own account cannot:

- no GitHub account is linked to theirs,
- their account cannot act on a repository that has the app, or
- GitHub refuses their request there.

GitHub then shows the app as the author. A report made through the app
opens a draft advisory as the app.

Where the app is not installed, a Point of Contact sends the request from
their own terminal with the GitHub CLI, `gh`. Link, Refresh, Pull, Push,
Report, and adding a collaborator each offer one `gh` command, and so does
opening a case from an advisory on the cases console. The command fetches the
request from here, sends it to GitHub with `gh api` as your account, and
posts GitHub's answer back. The tab records the answer as you and updates.
The command works once, for 15 minutes.

The tab cannot ask GitHub whether you administer the repository. For a
report, choose a draft advisory when you do, and a private report when you do
not.
