# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Fixtures do
  @moduledoc """
  Shared test data helpers: users, API keys and CVE records.
  """

  alias Varsel.Accounts.ApiKey
  alias Varsel.Accounts.User
  alias Varsel.CVE.CveRecord

  def register_user(handle, role \\ nil) do
    user =
      Ash.create!(
        User,
        %{
          user_info: %{
            "sub" => System.unique_integer([:positive]),
            "preferred_username" => handle,
            "name" => "#{handle} name",
            "email" => "#{handle}@example.com"
          },
          oauth_tokens: %{"access_token" => "gho_token"}
        },
        action: :register_with_github,
        authorize?: false
      )

    if role && role != user.role do
      Ash.update!(user, %{role: role}, action: :set_role, authorize?: false)
    else
      user
    end
  end

  @doc "Creates an API key for `user` and returns `{api_key, plaintext}`."
  def create_api_key(user, attrs \\ %{}) do
    api_key =
      Ash.create!(ApiKey, Map.put_new(attrs, :name, "test key"),
        action: :create,
        actor: user
      )

    {api_key, api_key.__metadata__.plaintext_api_key}
  end

  def reserved_cve_record(cve_id) do
    year = cve_id |> String.split("-") |> Enum.at(1)

    reservation_json = %{
      "cve_id" => cve_id,
      "cve_year" => year,
      "owning_cna" => "EEF",
      "reserved" => "#{year}-01-01T00:00:00.000Z",
      "state" => "RESERVED"
    }

    Ash.create!(CveRecord, %{reservation_json: reservation_json},
      action: :reserve,
      authorize?: false
    )
  end

  def published_cve_record(cve_id, title) do
    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.1",
      "cveMetadata" => %{"cveId" => cve_id, "state" => "PUBLISHED"},
      "containers" => %{"cna" => %{"title" => title}}
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end
end
