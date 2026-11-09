# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.DevEmailPreviewController do
  @moduledoc """
  Dev-only preview of every email `Varsel.Notifications.Emails` builds, with
  the HTML and text parts side by side, rendered from sample data so no
  delivery or database row is needed.
  """
  use VarselWeb, :controller

  alias Varsel.Accounts.User
  alias Varsel.Cases.CaseInvite
  alias Varsel.Notifications.Emails
  alias Varsel.Notifications.Kind
  alias Varsel.Notifications.Notification

  @sample_case_id "00000000-0000-4000-8000-000000000001"

  def index(conn, %{"email" => slug}) do
    case Enum.find(samples(), &(&1.slug == slug)) do
      nil ->
        conn
        |> put_status(:not_found)
        |> render_preview(nil)

      sample ->
        render_preview(conn, sample)
    end
  end

  def index(conn, _params), do: render_preview(conn, hd(samples()))

  defp render_preview(conn, sample) do
    conn
    |> put_view(html: VarselWeb.DevEmailPreviewHTML)
    |> render(:index,
      samples: samples(),
      selected: sample,
      email: sample && sample.build.()
    )
  end

  defp samples do
    immediate =
      for kind <- Kind.values() do
        %{
          slug: "immediate-#{kind}",
          group: "Immediate",
          label: Kind.label(kind),
          build: fn -> Emails.immediate_email(sample_user(), notification(kind)) end
        }
      end

    digest = %{
      slug: "digest",
      group: "Digest",
      label: "Daily digest",
      build: fn ->
        notifications =
          Enum.flat_map(
            [comment_posted: 3, proposal_opened: 2, case_published: 1],
            fn {kind, count} -> List.duplicate(notification(kind), count) end
          )

        Emails.digest_email(sample_user(), notifications)
      end
    }

    invites =
      for role <- CaseInvite.Role.values(), strategy <- CaseInvite.Strategy.values() do
        %{
          slug: "invite-#{role}-#{strategy}",
          group: "Case invite",
          label: "#{String.capitalize(to_string(role))} (#{strategy})",
          build: fn ->
            Emails.invite_email(%CaseInvite{
              email: "invitee@example.com",
              strategy: strategy,
              username: "octo-invitee",
              role: role,
              case_id: @sample_case_id
            })
          end
        }
      end

    immediate ++ [digest] ++ invites
  end

  defp sample_user, do: %User{notification_email: "reviewer@example.com"}

  defp notification(kind), do: %Notification{kind: kind, case_id: @sample_case_id}
end
