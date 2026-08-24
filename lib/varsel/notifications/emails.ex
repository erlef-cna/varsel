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
  alias Varsel.Mailer
  alias Varsel.Notifications.Kind
  alias Varsel.Notifications.Notification

  @doc """
  Builds the one-event notification email for `user`.
  """
  @spec immediate_email(User.t(), Notification.t()) :: Swoosh.Email.t()
  def immediate_email(user, notification) do
    new()
    |> to(to_string(user.notification_email))
    |> from(from_address())
    |> subject("EEF CNA: #{Kind.label(notification.kind)}")
    |> text_body(immediate_body(notification))
  end

  @doc """
  Builds the daily digest email for `user`, listing `notifications` grouped
  by kind.
  """
  @spec digest_email(User.t(), [Notification.t()]) :: Swoosh.Email.t()
  def digest_email(user, notifications) do
    new()
    |> to(to_string(user.notification_email))
    |> from(from_address())
    |> subject("EEF CNA: your daily notification digest")
    |> text_body(digest_body(notifications))
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

  defp immediate_body(notification) do
    """
    #{Kind.description(notification.kind)}

    #{subject_url(notification)}

    Change what you're notified about: #{url(~p"/settings/notifications")}
    """
  end

  defp digest_body(notifications) do
    lines =
      notifications
      |> Enum.group_by(& &1.kind)
      |> Enum.map(fn {kind, group} -> {Kind.label(kind), length(group)} end)
      |> Enum.sort_by(fn {label, _count} -> label end)
      |> Enum.map_join("\n", fn {label, count} -> "#{count} × #{label}" end)

    """
    Since your last digest:

    #{lines}

    See them all: #{url(~p"/notifications")}

    Change what you're notified about: #{url(~p"/settings/notifications")}
    """
  end

  defp subject_url(%Notification{kind: :report_submitted}), do: url(~p"/reports")

  defp subject_url(%Notification{case_id: case_id}) when not is_nil(case_id) do
    url(~p"/cases/#{case_id}")
  end

  defp from_address do
    Application.fetch_env!(:varsel, :cna_email_from)
  end
end
