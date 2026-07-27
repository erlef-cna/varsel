# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.ResolveOauthIdentity do
  @moduledoc """
  Decides which account an OAuth sign-in belongs to.

  Signing in:

    * The provider account is already linked — sign in as whoever holds it.
    * It is not, and no other identity reports its address — register.
    * It is not, but another identity does report that address — refuse, and
      say which provider to sign in with instead. Linking is then something
      they do from a session they have already proven.

  Linking (`:linking_user_id` in the action's context, put there by
  `VarselWeb.Plugs.OauthLinking`):

    * The provider account already belongs to someone else — refuse, rather
      than switch the session to them.
    * Otherwise attach it to the account the session named.

  The addresses compared are the ones each identity reports, which is what
  `user_identities_one_account_per_email` enforces underneath.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.OAuth2
  alias AshAuthentication.Strategy.OAuth2.UserResolver
  alias AshAuthentication.UserIdentity

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    with {:ok, strategy} <- Info.strategy_for_action(changeset.resource, changeset.action.name),
         {:ok, uid} <- uid(changeset, strategy),
         {:ok, changeset} <- resolve(changeset, strategy, uid, context) do
      Changeset.after_action(changeset, &attach_identity(&1, &2, strategy, context))
    else
      {:error, changeset} -> changeset
      :error -> changeset
    end
  end

  defp resolve(changeset, strategy, uid, context) do
    identity = fetch_identity(strategy, uid, context)
    linking_user_id = changeset.context[:linking_user_id]

    case {identity, linking_user_id} do
      # Known provider account, and not mid-link: sign in as its holder.
      {{:ok, identity}, nil} ->
        {:ok, use_account(changeset, identity.user_id)}

      # Known provider account that is already this account's: nothing to do
      # beyond refreshing the identity row, which the after_action handles.
      {{:ok, %{user_id: user_id}}, user_id} ->
        {:ok, use_account(changeset, user_id)}

      # Known provider account belonging to somebody else. Signing in as them
      # is right; doing it *during a link* would swap the session for the very
      # account they were adding to.
      {{:ok, _identity}, _linking_user_id} ->
        refuse(changeset, strategy, "That account already signs in to a different account here")

      # New provider account, mid-link: attach it to the account that asked,
      # unless the address is already spoken for elsewhere.
      {:error, linking_user_id} when not is_nil(linking_user_id) ->
        with {:ok, changeset} <- refuse_if_address_taken(changeset, strategy, context) do
          {:ok, use_account(changeset, linking_user_id)}
        end

      # New provider account, ordinary sign-in.
      {:error, nil} ->
        refuse_if_address_taken(changeset, strategy, context)
    end
  end

  # One address belongs to one account, so an account already reporting it is
  # the same person arriving by a second door. We will not take the provider's
  # word for that — signing in with the first provider is what proves it — so
  # the way through is to sign in there and link this one from that session.
  defp refuse_if_address_taken(changeset, strategy, context) do
    case sibling_identity(changeset, strategy, context) do
      {:ok, identity} ->
        refuse(
          changeset,
          strategy,
          "An account here already uses that email address, signed in with #{identity.strategy}"
        )

      :error ->
        {:ok, changeset}
    end
  end

  # Resolve the create onto an existing account by primary key. The register
  # action carries no `upsert_identity`, so Ash upserts on the primary key —
  # which is the only thing here that actually names an account.
  defp use_account(changeset, user_id), do: Changeset.force_change_attribute(changeset, :id, user_id)

  defp uid(changeset, strategy) do
    changeset
    |> Changeset.get_argument(:user_info)
    |> OAuth2.uid_from_user_info()
    |> case do
      nil -> refuse(changeset, strategy, "Provider did not return a stable `sub`/`uid` claim")
      uid -> {:ok, uid}
    end
  end

  defp fetch_identity(strategy, uid, context),
    do: UserResolver.fetch_identity(strategy, uid, Ash.Context.to_opts(context))

  # An identity of *another* account already reporting the address this one
  # just did. The account being linked to may of course already report it
  # itself — two of your own providers naming the same address is one person
  # with one address, which is what the constraint underneath also allows.
  defp sibling_identity(changeset, strategy, context) do
    email = changeset |> Changeset.get_argument(:user_info) |> Map.get("email")
    ours = changeset.context[:linking_user_id]

    if is_nil(email) do
      :error
    else
      strategy.identity_resource
      |> Ash.Query.filter(email == ^email)
      |> exclude_own_identities(ours)
      |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
      |> Ash.read_one(Ash.Context.to_opts(context))
      |> case do
        {:ok, nil} -> :error
        {:ok, identity} -> {:ok, identity}
        {:error, _error} -> :error
      end
    end
  end

  defp exclude_own_identities(query, nil), do: query
  defp exclude_own_identities(query, ours), do: Ash.Query.filter(query, user_id != ^ours)

  defp refuse(changeset, strategy, message) do
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
           message: message
         }
       )
     )}
  end

  # What IdentityChange's own after_action does: write the identity row for
  # whichever account the create resolved to.
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
