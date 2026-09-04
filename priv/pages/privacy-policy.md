%{
  title: "Privacy Policy",
  description: "What personal data the EEF CNA holds, why, and for how long"
}
---

This policy applies to the EEF CNA service and any related services operated by
the Erlang Ecosystem Foundation ("EEF", "we"), a 501(c)(3) non-profit
organization in Sunnyvale, California.

We operate the EEF CVE Numbering Authority: taking in vulnerability reports
about BEAM ecosystem packages, coordinating them, and publishing the resulting
CVE records. Handling a report means handling information about the people
involved in it.

**We hold personal data only for as long as processing a report or its case
requires it.** What that means in practice is set out below.

Questions, or any request about your own data: [get in touch](/contact).

## Data you give us

**Your account.** Signing in with GitHub or hex.pm creates an account here. It
holds the display name and username that provider reports, an email address to
notify you at, and the access and refresh tokens needed to keep the sign-in
working. We never receive your password.

**Your sessions.** Each sign-in records the IP address and browser it came from,
so you can see where your account is signed in and end a session you do not
recognise. Look under *Sessions* in your account settings. A session's record
goes when it expires or when you end it.

**What you write.** Reports you submit, and the comments, proposals and case
content you author. Vulnerability coordination is a written record, and that
record is the point of the service.

## Data other systems report to us

Vulnerability reports can be forwarded by an upstream system rather than typed
here. Today that is hex.pm's package report form.

When hex.pm forwards a report, it tells us **who reported it and who maintains
the reported package**, each as a name, a hex.pm username, and the email address
hex.pm holds for them. We did not collect this from those people, and they may
have no account here.

That information exists so a coordinator can bring the right people into the
case. Accordingly:

- **While a report is being triaged, only the CNA's points of contact see it.**
  A reporter is not shown the package's maintainers, and maintainers are not
  shown who reported.
- **Coordinating a vulnerability means working together.** If a report becomes
  a case, the reporter and the maintainers are invited onto it, and from then on
  they can see each other's names and provider usernames, the same details
  anyone signed in here shows their collaborators.
- **Email addresses are never part of that.** The address hex.pm gave us is
  visible only to points of contact, and is never shown to anyone else on the
  case.
- **An invite tells you once, by email.** When a coordinator invites you onto
  a case by your hex.pm username, we ask hex.pm for the primary address of
  that account and send one email with a sign-in link. That address is sent
  even when you hide it on your public hex.pm profile. For a GitHub username
  we use the public address on the profile. When the provider lists no
  address, the coordinator may enter one they found for you. The invite holds
  that address, visible to points of contact only, and drops it when you sign
  in or the invite is withdrawn.
- **It is deleted as soon as the report is resolved.** When a report becomes a
  case, is rejected, or is withdrawn, the contact details we were given are
  erased. What remains is the case and the people who joined it.
- **If you have an account here, it becomes yours.** A forwarded report naming
  your username is linked to your account, and the separately reported contact
  details are dropped. Your account holds them from then on, under your
  control.

## Data we collect automatically

Server logs record requests: an IP address, the page requested, the user agent,
and the time. They exist to keep the service running and secure.

**There is no analytics, advertising, or tracking of any kind.** We set no
tracking cookies, embed no third-party scripts or SDKs, use no pixels, and build
no profiles. The only cookie is the one that keeps you signed in. We do not send
marketing email.

One thing does leave the page: **profile pictures are loaded from GitHub or
Gravatar**, so those sites see the IP address of whoever is looking. Gravatar is
asked for a picture using a one-way hash of the address, which lets it match an
address someone already knows but does not disclose the address itself.

## What we publish

Published CVE records are public by design, worldwide and permanently. They can
name people who asked to be credited for a discovery, and those credits are part
of the public record.

Credits are published only when they are given. If you would rather a credit
were removed, [tell us](/contact) and we will remove it from our records.
Be aware of what that can and cannot achieve: CVE data is distributed by design,
and once a record is published it is copied by MITRE, by vulnerability
databases, and by anyone else consuming our feeds. We can correct what we
publish; we cannot reach the copies.

Nothing else about an account is ever published: not your email address, not
your sign-in provider, not the reports you filed.

## Who else sees it

Published records go to **MITRE**, which operates the CVE program, and we
publish them ourselves as an **OSV** feed. From both, they reach everyone who
consumes vulnerability data.

Two providers process data on our behalf, and only on our behalf: the host our
servers run on, and the provider that delivers our email. They are bound to act
on our instructions, keep what they process confidential, help us answer
requests about your data, tell us about breaches, and return or delete
everything when we part ways.

Your data is not sold, rented, or shared for anyone else's purposes, and no
advertising or analytics company receives it.

We may disclose information where the law requires it, such as a subpoena or
similar legal process, or where we believe in good faith that disclosure is
necessary to protect someone's safety or our rights. Service providers acting on our
behalf may process data for us; they have no independent use of it and are bound
to handle it as this policy describes.

## International transfers

We are established in the United States, so data about people in the European
Economic Area or the UK is transferred out of it.

Where the law requires safeguards for that, we rely on the **Standard
Contractual Clauses** approved by the European Commission. Our hosting provider
has entered into them with us, and they extend to the sub-processors it uses.

## How long we keep it

- **Forwarded contact details:** deleted when the report they came with is
  accepted, rejected or withdrawn.
- **Your account:** kept while the account exists. Delete it and it goes, apart
  from the audit-trail entries described below.
- **Server logs:** kept only as long as running and securing the service
  requires, and subject to our hosting provider's retention.
- **Published CVE records:** permanent, by design. They are a public reference
  others rely on.
- **Anything the law requires us to keep:** for as long as it requires.

**Changes are recorded separately.** Every change to a record is written to an
append-only audit trail, so we can reconstruct who changed what during a
coordination. Entries outlive the records they describe, and they name the
account that made each change.

**Email addresses are deliberately kept out of that trail**, as are access
tokens. What it holds is the same names and provider usernames your
collaborators already see. It is not shown anywhere in the interface, to the
CNA's points of contact or anyone else, and not over any API: reaching it takes
direct database access.

## Your rights

**Delete your account yourself, at any time.** Sign in and use *Delete account*
in your account settings. It removes your account, your linked providers, your
API keys, and your case assignments immediately.

What you *wrote* stays, and loses its author. A discussion does not stop being a
discussion because one participant leaves, and a published CVE record cannot be
unpublished. The audit trail described above also keeps its entries, including
the name and the account id that made each change. This is the limit of what
deleting an account can do, and it is worth knowing before you write.

You can also ask us to give you a copy of your data, correct it, restrict or
object to how we use it, or delete it, subject to any legal obligation to keep
it. [Get in touch](/contact).

**If you are in the EEA or the UK**, these are your rights under the GDPR, and
you may complain to a data protection authority: the one where you live, where
you work, or where you think we got it wrong.

We process personal data on the basis of our **legitimate interest** in
coordinating vulnerability disclosure, which is work in the public interest.
That covers both people who signed in here, whose data goes when they delete
their account, and people an upstream system named to us, whose details we hold
only until the report they came with is resolved and then erase.

The rights above are open to anyone who asks, wherever they live. **We do not
sell or share personal information**, to anyone, for any purpose.

You can stop us collecting anything further by ceasing to use the service,
though that alone does not delete what we already hold. To do that, use *Delete
account*, or write to us.

## Keeping it safe

Access to reports and cases is restricted to the people working on them.
Everything travels over HTTPS. Credentials are stored hashed or encrypted, never
in plain text.

Our own security posture is described in
[THREAT_MODEL.md](https://github.com/erlef-cna/varsel/blob/main/THREAT_MODEL.md),
and vulnerabilities in this service can be reported through our
[Security Policy](/security-policy).

If a breach affects your personal data, we will notify you and the relevant
authority as the law requires, including what happened and what we are doing
about it.

## Children

This service is for people coordinating software vulnerabilities. It is not
directed at children, and we do not knowingly collect personal data from anyone
under 16. That covers both the US COPPA threshold of 13 and the higher age some
EU member states set under Article 8 of the GDPR.

If you believe a child has given us personal data, [tell us](/contact) and we
will remove it.

## Changes

We will update this page when what we do changes, and the date below will say
when. Every previous version is in
[the page's history](https://github.com/erlef-cna/varsel/commits/main/priv/pages/privacy-policy.md),
along with what changed and when.

This policy is effective as of 2026-08-12.
