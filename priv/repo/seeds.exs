# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# In dev it gives the mock POC (the "POC" entry under MOCK SIGN IN) two unread
# notifications of every kind, spread over two seeded cases. Reseeding replaces
# those notifications and reuses the cases (marker: notifications-seed).

defmodule Seeds.Notifications do
  @moduledoc false

  import Ecto.Query

  alias Varsel.Accounts.User
  alias Varsel.Notifications.Kind
  alias Varsel.Repo

  @marker "notifications-seed"

  def run do
    poc = mock_poc()
    cases = Enum.map(1..2, &seed_case(poc, &1))
    case_ids = Enum.map(cases, &Ecto.UUID.dump!(&1.id))

    Repo.delete_all(
      from(n in "notifications",
        where: n.user_id == ^Ecto.UUID.dump!(poc.id) and n.case_id in ^case_ids
      )
    )

    for kind <- Kind.values(), kase <- cases do
      Varsel.Notifications.record_notification!(
        %{kind: kind, user_id: poc.id, case_id: kase.id, email_requested: false},
        authorize?: false
      )
    end

    IO.puts("Seeded #{length(Kind.values()) * 2} notifications for the mock POC.")
  end

  # The same upsert the mock sign-in performs, so signing in as POC in the
  # browser lands on exactly this user.
  defp mock_poc do
    {_uid, label, _role} = List.keyfind(Varsel.Accounts.Strategy.Mock.roles(), "poc", 0)

    Ash.create!(
      User,
      %{
        user_info: %{
          "sub" => "poc",
          "preferred_username" => "mock-poc",
          "name" => "Mock #{label}",
          "email" => "mock-poc@example.com"
        },
        oauth_tokens: %{},
        role: :poc
      },
      action: :register_with_mock,
      authorize?: false
    )
  end

  defp seed_case(poc, n) do
    title = "Seeded notification case #{n}"

    existing =
      Repo.one(
        from(c in "cases",
          where: c.title == ^title and like(c.internal_notes, ^"%#{@marker}%"),
          select: c.id,
          limit: 1
        )
      )

    case existing do
      nil ->
        Varsel.Cases.open_case!(
          %{
            title: title,
            internal_notes: "Seeded by priv/repo/seeds.exs (#{@marker}); safe to delete."
          },
          actor: poc
        )

      id ->
        Varsel.Cases.get_case!(Ecto.UUID.cast!(id), actor: poc)
    end
  end
end

if Mix.env() == :dev do
  Seeds.Notifications.run()
end
