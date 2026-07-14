# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.PaperTrailTest do
  use Varsel.DataCase, async: false

  alias Varsel.Accounts.User
  alias Varsel.Accounts.UserIdentity

  defp register_user(handle \\ nil) do
    handle = handle || "user#{System.unique_integer([:positive])}"

    User
    |> Ash.Changeset.for_create(
      :register_with_github,
      %{
        user_info: %{
          "sub" => System.unique_integer([:positive]),
          "preferred_username" => handle,
          "name" => "Test User",
          "email" => "#{handle}@example.com"
        },
        oauth_tokens: %{"access_token" => "gho_secret_token", "refresh_token" => "ghr_secret"}
      },
      authorize?: false
    )
    |> Ash.create!(authorize?: false)
  end

  test "registering via GitHub creates a user version" do
    user = register_user()

    versions =
      user
      |> Ash.load!([:paper_trail_versions], authorize?: false)
      |> Map.fetch!(:paper_trail_versions)

    assert [version] = versions
    assert version.version_action_name == :register_with_github
    assert version.changes["email"] == user.email
  end

  test "changing a user's role records the change and the acting user" do
    user = register_user()
    poc = register_user()
    poc = Ash.update!(poc, %{role: :poc}, action: :set_role, authorize?: false)

    Ash.update!(user, %{role: :supporter}, action: :set_role, actor: poc)

    versions =
      user
      |> Ash.load!([:paper_trail_versions], authorize?: false)
      |> Map.fetch!(:paper_trail_versions)

    update_version = Enum.find(versions, &(&1.version_action_name == :set_role))
    assert update_version.changes == %{"role" => "supporter"}
    assert update_version.user_id == poc.id
  end

  test "user identity versions never contain OAuth tokens" do
    register_user()

    versions = Ash.read!(UserIdentity.Version, authorize?: false)
    assert versions != []

    for version <- versions do
      refute Map.has_key?(version.changes, "access_token")
      refute Map.has_key?(version.changes, "access_token_expires_at")
      refute Map.has_key?(version.changes, "refresh_token")
    end
  end
end
