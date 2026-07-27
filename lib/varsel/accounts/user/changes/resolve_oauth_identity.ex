# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.ResolveOauthIdentity do
  @moduledoc """
  Decides which account an OAuth sign-in belongs to, adding the "attach this to
  the account I am already signed in as" case the library has no notion of.

  An ordinary sign-in is entirely
  `AshAuthentication.Strategy.OAuth2.IdentityChange`'s business, and is
  delegated untouched. A link differs in one way: the account is already known,
  so instead of resolving one from what the provider said, the identity is
  attached to the account the session named.

  That distinction matters because the library deliberately refuses a provider
  whose address an account already holds — an address is not proof of
  ownership, so accepting it would mean controlling an address is enough to
  reach an account. During a link the caller has *already* proven they hold the
  account, by being signed in to it, which is the stronger claim that check
  exists to demand.

  "Mid-link" is `:linking_user_id` in the action's context, put there by
  `VarselWeb.Plugs.OauthLinking` from the session the Link button wrote.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.OAuth2
  alias AshAuthentication.Strategy.OAuth2.IdentityChange
  alias AshAuthentication.Strategy.OAuth2.UserResolver
  alias AshAuthentication.UserIdentity

  @impl Ash.Resource.Change
  def change(changeset, opts, context) do
    case changeset.context[:linking_user_id] do
      nil -> IdentityChange.change(changeset, opts, context)
      user_id -> link_to(changeset, user_id, context)
    end
  end

  defp link_to(changeset, linking_user_id, context) do
    with {:ok, strategy} <- Info.strategy_for_action(changeset.resource, changeset.action.name),
         :ok <- refuse_if_claimed(changeset, strategy, linking_user_id, context) do
      changeset
      # The account is settled, so there is nothing to resolve: point the
      # upsert at it and let the create land on that row.
      |> point_at(linking_user_id, context)
      |> Changeset.after_action(&attach_identity(&1, &2, strategy, context))
    else
      {:error, changeset} -> changeset
      :error -> changeset
    end
  end

  # The provider account already signs someone in. Outside a link that is
  # simply a sign-in as them; during one it would swap the session for the
  # account the caller was adding to, which is never what they meant.
  defp refuse_if_claimed(changeset, strategy, linking_user_id, context) do
    uid =
      changeset
      |> Changeset.get_argument(:user_info)
      |> OAuth2.uid_from_user_info()

    case UserResolver.fetch_identity(strategy, uid, Ash.Context.to_opts(context)) do
      {:ok, identity} when identity.user_id != linking_user_id ->
        {:error,
         Changeset.add_error(
           changeset,
           AuthenticationFailed.exception(
             strategy: strategy,
             changeset: changeset,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: changeset.action.name,
               message: "That account already signs in to a different account here"
             }
           )
         )}

      _ours_or_new ->
        :ok
    end
  end

  defp point_at(changeset, linking_user_id, context) do
    case Ash.get(changeset.resource, linking_user_id, Ash.Context.to_opts(context)) do
      {:ok, user} ->
        Changeset.force_change_attribute(changeset, :notification_email, user.notification_email)

      {:error, _error} ->
        changeset
    end
  end

  # What IdentityChange's own after_action does: write the identity row for
  # whichever user the create resolved to.
  defp attach_identity(changeset, user, strategy, context) do
    cfg = UserIdentity.Info.user_identity_options(strategy.identity_resource)

    attrs = %{
      cfg.user_id_attribute_name => user.id,
      :user_info => Changeset.get_argument(changeset, :user_info),
      :oauth_tokens => Changeset.get_argument(changeset, :oauth_tokens),
      :strategy => to_string(strategy.name)
    }

    case UserIdentity.Actions.upsert(
           strategy.identity_resource,
           attrs,
           Ash.Context.to_opts(context)
         ) do
      {:ok, _identity} -> {:ok, user}
      {:error, error} -> {:error, error}
    end
  end
end
