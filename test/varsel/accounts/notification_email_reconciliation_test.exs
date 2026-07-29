# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.NotificationEmailReconciliationTest do
  @moduledoc """
  A notification email must stay attested by a linked identity: when a
  provider re-reports a different address, or an identity is unlinked, the
  account falls back to an address some identity still reports — nil if none.
  """

  use Varsel.DataCase, async: false

  alias Varsel.Accounts
  alias Varsel.Accounts.User
  alias Varsel.Accounts.UserIdentity

  require Ash.Query

  # Mimics how AshAuthentication invokes the register action: no actor,
  # authorization on, the interaction marked in the changeset context. The
  # reconcile therefore runs under its real mid-sign-in authorization.
  defp sign_in(sub, email) do
    user_info =
      Map.merge(
        %{"sub" => sub, "preferred_username" => "user-#{sub}", "name" => "User #{sub}"},
        if(email, do: %{"email" => email}, else: %{})
      )

    Ash.create!(
      User,
      %{user_info: user_info, oauth_tokens: %{"access_token" => "token"}},
      action: :register_with_github,
      context: %{private: %{ash_authentication?: true}}
    )
  end

  # An additional provider on an existing account, or — with the same uid — a
  # later sign-in of that provider reporting a different address.
  defp link_identity(user, strategy, uid, email) do
    Ash.create!(
      UserIdentity,
      %{
        user_id: user.id,
        strategy: strategy,
        user_info: %{"sub" => uid, "preferred_username" => uid, "email" => email},
        oauth_tokens: %{"access_token" => "token"}
      },
      action: :upsert,
      context: %{private: %{ash_authentication?: true}}
    )
  end

  defp reload(user), do: Ash.get!(User, user.id, authorize?: false)

  defp identity(user, strategy) do
    user
    |> Ash.load!([:identities], authorize?: false)
    |> Map.fetch!(:identities)
    |> Enum.find(&(to_string(&1.strategy) == strategy))
  end

  defp unique_sub, do: "sub-#{System.unique_integer([:positive])}"

  test "a changed provider address follows onto the notification email" do
    sub = unique_sub()
    user = sign_in(sub, "old@example.com")

    sign_in(sub, "new@example.com")

    assert to_string(reload(user).notification_email) == "new@example.com"
  end

  test "an address another identity still reports stays put" do
    sub = unique_sub()
    hex_uid = unique_sub()
    user = sign_in(sub, "one@example.com")
    link_identity(user, "hex", hex_uid, "one@example.com")

    link_identity(user, "hex", hex_uid, "two@example.com")

    assert to_string(reload(user).notification_email) == "one@example.com"
  end

  test "an explicitly chosen other identity's address survives a provider change" do
    sub = unique_sub()
    user = sign_in(sub, "a@example.com")
    link_identity(user, "hex", unique_sub(), "b@example.com")
    user = reload(user)

    Accounts.set_user_notification_email!(user, %{notification_email: "b@example.com"}, actor: user)

    sign_in(sub, "c@example.com")

    assert to_string(reload(user).notification_email) == "b@example.com"
  end

  test "a capitalisation difference is not a change" do
    sub = unique_sub()
    user = sign_in(sub, "old@example.com")

    sign_in(sub, "OLD@EXAMPLE.COM")

    # Reconciling would have written the provider's casing; the stored casing
    # surviving shows the covered check matched case-insensitively and the
    # user row was left untouched.
    assert to_string(reload(user).notification_email) == "old@example.com"

    versions =
      User.Version
      |> Ash.Query.filter(version_source_id == ^user.id and version_action_name == :reconcile_notification_email)
      |> Ash.read!(authorize?: false)

    assert versions == []
  end

  test "unlinking the identity backing the address falls back to a remaining one" do
    user = sign_in(unique_sub(), "a@example.com")
    link_identity(user, "hex", unique_sub(), "b@example.com")

    Accounts.unlink_provider!(identity(user, "github"), actor: reload(user))

    assert to_string(reload(user).notification_email) == "b@example.com"
  end

  test "unlinking an identity not backing the address leaves it alone" do
    user = sign_in(unique_sub(), "a@example.com")
    link_identity(user, "hex", unique_sub(), "b@example.com")

    Accounts.unlink_provider!(identity(user, "hex"), actor: reload(user))

    assert to_string(reload(user).notification_email) == "a@example.com"
  end

  test "with no identity left the address clears" do
    user = sign_in(unique_sub(), "a@example.com")

    # The destroy policy forbids removing the last identity; bypassing it here
    # exercises the reconcile's own no-identities fallback.
    Ash.destroy!(identity(user, "github"), action: :destroy, authorize?: false)

    assert reload(user).notification_email == nil
  end

  test "an address already claimed by another account falls back to nil" do
    other = sign_in(unique_sub(), "other@example.com")

    # A stale claim: the other account's notification email no longer backed
    # by any of its identities — exactly what this reconcile prevents from now
    # on, planted directly to simulate a pre-existing squat.
    Ash.update!(
      reload(other),
      %{notification_email: "contested@example.com"},
      action: :reconcile_notification_email,
      authorize?: false
    )

    sub = unique_sub()
    user = sign_in(sub, "mine@example.com")

    sign_in(sub, "contested@example.com")

    assert reload(user).notification_email == nil
    assert to_string(reload(other).notification_email) == "contested@example.com"
  end
end
