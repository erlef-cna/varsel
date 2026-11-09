# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Emails do
  @moduledoc """
  Builds and delivers notification emails: one per event
  (`deliver_immediate/2`) or a daily rollup (`deliver_digest/3`).

  Email offers no encryption we can rely on end to end, so anything sensitive
  about a case or report has to stay behind the authenticated console.
  """

  use VarselWeb, :verified_routes

  import Swoosh.Email

  alias Varsel.Accounts.User
  alias Varsel.Cases.CaseInvite
  alias Varsel.Mailer
  alias Varsel.Notifications.Emails.DigestTemplate
  alias Varsel.Notifications.Emails.ImmediateTemplate
  alias Varsel.Notifications.Emails.InviteTemplate
  alias Varsel.Notifications.Emails.MaintainerInviteTemplate
  alias Varsel.Notifications.Kind
  alias Varsel.Notifications.Notification
  alias VarselWeb.SignInPath

  # The non-response window in /maintainer-process, "Timelines & Embargo".
  @maintainer_response_days 14

  @doc """
  Builds the one-event notification email for `user`.
  """
  @spec immediate_email(User.t(), Notification.t()) :: Swoosh.Email.t()
  def immediate_email(user, notification) do
    subject = "EEF CNA: #{Kind.label(notification.kind)}"

    assigns = %{
      subject: subject,
      preview: Kind.description(notification.kind),
      reason: "You get this email because of your notification settings.",
      label: Kind.label(notification.kind),
      description: Kind.description(notification.kind),
      case_url: subject_url(notification),
      settings_url: url(~p"/settings/notifications")
    }

    new()
    |> to(to_string(user.notification_email))
    |> from(from_address())
    |> subject(subject)
    |> text_body(immediate_body(assigns))
    |> html_body(assigns |> with_letterhead() |> ImmediateTemplate.render())
  end

  @doc """
  Builds the daily digest email for `user`, listing `notifications` grouped
  by kind.
  """
  @spec digest_email(User.t(), [Notification.t()]) :: Swoosh.Email.t()
  def digest_email(user, notifications) do
    subject = "EEF CNA: your daily notification digest"

    assigns = %{
      subject: subject,
      preview: "What happened since your last digest.",
      reason: "You get this daily digest because of your notification settings.",
      lines: digest_lines(notifications),
      notifications_url: url(~p"/notifications"),
      settings_url: url(~p"/settings/notifications")
    }

    new()
    |> to(to_string(user.notification_email))
    |> from(from_address())
    |> subject(subject)
    |> text_body(digest_body(assigns))
    |> html_body(assigns |> with_letterhead() |> DigestTemplate.render())
  end

  @doc """
  Delivers the one-event notification email for `notification`'s user.
  Skips silently when the user has no notification email on file.
  """
  @spec deliver_immediate(Notification.t(), map()) :: :ok
  def deliver_immediate(notification, context) do
    user = Ash.get!(User, notification.user_id, Varsel.ObanContext.forward(context))

    if user.notification_email do
      {:ok, _metadata} =
        user
        |> immediate_email(notification)
        |> Mailer.deliver()
    end

    :ok
  end

  @doc """
  Delivers the daily digest email for `user_id`'s pending `notifications`.
  Skips silently when the user has no notification email on file.
  """
  @spec deliver_digest(Ash.UUID.t(), [Notification.t()], map()) :: :ok
  def deliver_digest(user_id, notifications, context) do
    user = Ash.get!(User, user_id, Varsel.ObanContext.forward(context))

    if user.notification_email do
      {:ok, _metadata} =
        user
        |> digest_email(notifications)
        |> Mailer.deliver()
    end

    :ok
  end

  @doc """
  Builds the email that tells someone a case invite names their provider
  account. A maintainer's also states the CNA's non-response policy.
  """
  @spec invite_email(CaseInvite.t()) :: Swoosh.Email.t()
  def invite_email(invite) do
    assigns = %{
      provider: provider_name(invite.strategy),
      username: invite.username,
      sign_in_url: VarselWeb.Endpoint.url() <> SignInPath.for(~p"/cases/#{invite.case_id}"),
      process_url: url(~p"/maintainer-process"),
      other_provider: provider_name(other_strategy(invite.strategy)),
      account_url: url(~p"/settings/account")
    }

    new()
    |> to(to_string(invite.email))
    |> from(from_address())
    |> invite_content(invite.role, assigns)
  end

  defp invite_content(email, :maintainer, assigns) do
    subject = "EEF CNA: review a possible vulnerability in your package"

    assigns =
      Map.merge(assigns, %{
        subject: subject,
        preview: "We'd like to work on it with you.",
        reason: "This email holds no details about the vulnerability. You read them after you sign in.",
        response_days: @maintainer_response_days
      })

    email
    |> subject(subject)
    |> text_body(maintainer_invite_body(assigns))
    |> html_body(assigns |> with_letterhead() |> MaintainerInviteTemplate.render())
  end

  defp invite_content(email, _role, assigns) do
    subject = "EEF CNA: join a vulnerability case"

    assigns =
      Map.merge(assigns, %{
        subject: subject,
        preview: "Sign in to open the case you were invited to.",
        reason: "This email holds no details about the case. You read them after you sign in."
      })

    email
    |> subject(subject)
    |> text_body(invite_body(assigns))
    |> html_body(assigns |> with_letterhead() |> InviteTemplate.render())
  end

  @doc "Delivers the invite email for `invite` to its stored address."
  @spec deliver_invite(CaseInvite.t()) :: :ok
  def deliver_invite(invite) do
    {:ok, _metadata} =
      invite
      |> invite_email()
      |> Mailer.deliver()

    :ok
  end

  defp invite_body(assigns) do
    """
    A coordinator at the Erlang Ecosystem Foundation (EEF) CNA invited you to work on a vulnerability case.

    The invite names your #{assigns.provider} account "#{assigns.username}". Sign in with that account to open the case:

    #{assigns.sign_in_url}

    Already signed up with #{assigns.other_provider}? Link #{assigns.provider} to that account first: #{assigns.account_url}

    Our Maintainer Process explains how a case runs and what to expect: #{assigns.process_url}

    This email holds no details about the case. You read them after you sign in.
    """
  end

  defp maintainer_invite_body(assigns) do
    """
    Hi,

    Someone reported a possible vulnerability in a package you maintain, and we at the Erlang Ecosystem Foundation (EEF) CNA are coordinating it. We opened a private case for it and invited you, so we can work on it together.

    The invite names your #{assigns.provider} account "#{assigns.username}". Sign in with that account to read the report:

    #{assigns.sign_in_url}

    Already signed up with #{assigns.other_provider}? Link #{assigns.provider} to that account first: #{assigns.account_url}

    If we don't hear from you within #{assigns.response_days} days, we may publish the CVE without a fix, so that people who depend on the package can protect themselves. If you need more time, just tell us. Our Maintainer Process walks through each step and its timelines: #{assigns.process_url}

    Until the CVE is out, please keep this private: no public issues, pull requests or commits about it, since those would tell attackers before users can upgrade.

    The EEF CNA

    This email holds no details about the vulnerability. You read them after you sign in.
    """
  end

  defp with_letterhead(assigns) do
    site_url = url(~p"/")

    Map.merge(assigns, %{
      site_url: site_url,
      site_host: URI.parse(site_url).host,
      logo_url: url(~p"/images/email/eef-mark-white.png"),
      process_url: url(~p"/maintainer-process"),
      policy_url: url(~p"/security-policy"),
      contact_url: url(~p"/contact"),
      year: Date.utc_today().year
    })
  end

  defp other_strategy(:github), do: :hex
  defp other_strategy(:hex), do: :github

  defp provider_name(:github), do: "GitHub"
  defp provider_name(:hex), do: "hex.pm"

  defp immediate_body(assigns) do
    """
    #{assigns.description}

    #{assigns.case_url}

    Change what you're notified about: #{assigns.settings_url}
    """
  end

  defp digest_lines(notifications) do
    notifications
    |> Enum.group_by(& &1.kind)
    |> Enum.map(fn {kind, group} -> {Kind.label(kind), length(group)} end)
    |> Enum.sort_by(fn {label, _count} -> label end)
  end

  defp digest_body(assigns) do
    lines = Enum.map_join(assigns.lines, "\n", fn {label, count} -> "#{count} × #{label}" end)

    """
    Since your last digest:

    #{lines}

    See them all: #{assigns.notifications_url}

    Change what you're notified about: #{assigns.settings_url}
    """
  end

  defp subject_url(%Notification{kind: :mentioned, case_id: case_id}) do
    url(~p"/cases/#{case_id}/comments")
  end

  defp subject_url(%Notification{case_id: case_id}) do
    url(~p"/cases/#{case_id}")
  end

  defp from_address do
    Application.fetch_env!(:varsel, :cna_email_from)
  end
end
