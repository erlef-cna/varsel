# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AccountSettingsLive do
  @moduledoc """
  Self-service account settings for any logged-in user.

  `:set_notification_email` is authorized to the account holder alone — not
  even a POC repoints someone else's address.
  """
  use VarselWeb, :live_view

  import VarselWeb.UserComponents, only: [avatar_disc: 1]

  alias AshAuthentication.TokenResource.Actions, as: TokenActions
  alias Varsel.Accounts
  alias Varsel.Accounts.Token
  alias VarselWeb.UserAgent

  @impl Phoenix.LiveView
  def mount(_params, session, socket) do
    {:ok,
     socket
     |> assign(page_title: "Account", current_session_jti: session["current_session_jti"])
     |> assign_account()
     |> assign_sessions()}
  end

  @impl Phoenix.LiveView
  def handle_event("delete_account", _params, socket) do
    actor = socket.assigns.current_user

    case Accounts.delete_user(actor, actor: actor) do
      :ok ->
        # Deleting an account revokes its tokens, so the session cookie the
        # browser still holds no longer authenticates anything — landing on a
        # public page is all that is left to do.
        {:noreply,
         socket
         |> put_flash(:info, "Your account has been deleted.")
         |> push_navigate(to: ~p"/")}

      {:error, _error} ->
        {:noreply, put_flash(socket, :error, "Could not delete your account.")}
    end
  end

  @impl Phoenix.LiveView
  def handle_event("set_notification_email", %{"notification_email" => email}, socket) do
    actor = socket.assigns.current_user

    socket =
      case Accounts.set_user_notification_email(
             socket.assigns.account,
             %{notification_email: email},
             actor: actor
           ) do
        {:ok, _user} ->
          socket
          |> assign_account()
          |> put_flash(:info, "Notification email set to #{email}.")

        {:error, _error} ->
          put_flash(socket, :error, "Could not set the notification email.")
      end

    {:noreply, socket}
  end

  @impl Phoenix.LiveView
  def handle_event("unlink_provider", %{"identity_id" => identity_id}, socket) do
    actor = socket.assigns.current_user
    identity = Enum.find(socket.assigns.account.identities, &(&1.id == identity_id))

    socket =
      case Accounts.unlink_provider(identity, actor: actor) do
        :ok ->
          socket
          |> assign_account()
          |> put_flash(:info, "Unlinked #{provider_label(identity.strategy)}.")

        {:error, _error} ->
          put_flash(socket, :error, "Could not unlink that provider.")
      end

    {:noreply, socket}
  end

  @impl Phoenix.LiveView
  def handle_event("revoke_session", %{"jti" => jti}, socket) do
    actor = socket.assigns.current_user

    # The current session has no button, so this can only arrive hand-made.
    socket =
      cond do
        jti == socket.assigns.current_session_jti ->
          put_flash(socket, :error, "Use sign out to end the session you are using.")

        not Enum.any?(socket.assigns.sessions, &(&1.jti == jti)) ->
          put_flash(socket, :error, "That session is no longer signed in.")

        true ->
          revoke_session(socket, actor, jti)
      end

    {:noreply, assign_sessions(socket)}
  end

  def handle_event("revoke_other_sessions", _params, socket) do
    actor = socket.assigns.current_user
    others = Enum.reject(socket.assigns.sessions, & &1.current?)

    socket =
      if Enum.all?(others, &(revoke(actor, &1.jti) == :ok)) do
        put_flash(socket, :info, "Signed out #{count_phrase(length(others))}.")
      else
        put_flash(socket, :error, "Could not sign out every other session.")
      end

    {:noreply, assign_sessions(socket)}
  end

  defp revoke_session(socket, actor, jti) do
    case revoke(actor, jti) do
      :ok -> put_flash(socket, :info, "Session signed out.")
      {:error, _error} -> put_flash(socket, :error, "Could not sign out that session.")
    end
  end

  # Flips the stored row rather than writing a second, orphaned one.
  defp revoke(actor, jti) do
    TokenActions.revoke_jti(Token, jti, AshAuthentication.user_to_subject(actor), store_all_tokens?: true)
  end

  defp count_phrase(1), do: "1 other session"
  defp count_phrase(count), do: "#{count} other sessions"

  # The current session is shown but not revocable; sign out ends that one.
  defp assign_sessions(socket) do
    actor = socket.assigns.current_user
    current = socket.assigns.current_session_jti

    sessions =
      actor
      |> AshAuthentication.user_to_subject()
      |> Accounts.list_sessions!(actor: actor)
      |> Enum.map(fn token ->
        %{
          jti: token.jti,
          current?: token.jti == current,
          signed_in_at: token.created_at,
          user_agent: UserAgent.describe(get_in(token.extra_data, ["user_agent"])),
          ip: get_in(token.extra_data, ["ip"])
        }
      end)

    assign(socket, sessions: sessions)
  end

  defp assign_account(%{assigns: %{current_user: nil}}), do: raise(VarselWeb.UnauthorizedError)

  # The addresses to choose between are exactly what this user's providers
  # reported, deduplicated — the same address from two providers is one choice.
  defp assign_account(socket) do
    actor = socket.assigns.current_user

    account =
      Ash.load!(actor, [:avatar_url, :display_name, :identity_emails, :identities], actor: actor)

    linked = Map.new(account.identities, &{to_string(&1.strategy), &1})

    assign(socket,
      account: account,
      candidate_emails: candidate_emails(account),
      providers:
        Enum.map(oauth_strategies(), fn strategy ->
          identity = Map.get(linked, to_string(strategy.name))

          %{
            name: strategy.name,
            label: provider_label(strategy.name),
            identity_id: identity && identity.id,
            # Asked of the policy rather than reasoned about here, so the
            # button cannot drift from what is actually allowed — it refuses
            # the last provider, which would lock the account out.
            unlinkable?: not is_nil(identity) and Accounts.can_unlink_provider?(actor, identity)
          }
        end)
    )
  end

  # The addresses to choose between, each flagged if it is the one in use.
  # Compared and deduplicated as plain strings: these are case-insensitive
  # values, and `==`/`uniq`/`sort` would otherwise treat two spellings of one
  # address as two — which is exactly what the type exists to prevent.
  defp candidate_emails(account) do
    in_use = normalize(account.notification_email)

    account.identity_emails
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&to_string/1)
    |> Enum.uniq_by(&String.downcase/1)
    |> Enum.sort_by(&String.downcase/1)
    |> Enum.map(&%{email: &1, in_use?: normalize(&1) == in_use})
  end

  defp normalize(nil), do: nil
  defp normalize(value), do: value |> to_string() |> String.downcase()

  # Only providers this deployment actually offers; an unconfigured one has no
  # working callback, so a Link button for it would go nowhere.
  defp oauth_strategies do
    Varsel.Accounts.User
    |> AshAuthentication.Info.authentication_strategies()
    |> Enum.filter(&(&1.name in [:github, :hex] and Varsel.Secrets.strategy_enabled?(&1)))
  end

  # Accepts either form: strategies name themselves with atoms, identity rows
  # store the same name as a string.
  defp provider_label(strategy) when is_atom(strategy), do: strategy |> to_string() |> provider_label()

  defp provider_label("github"), do: "GitHub"
  defp provider_label("hex"), do: "Hex.pm"

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_user={@current_user} current_path={@current_path}>
      <.page_header>
        <:eyebrow>CNA Console</:eyebrow>
        <:title>Account</:title>
        <:subtitle>Your profile and how the CNA reaches you.</:subtitle>
      </.page_header>

      <.page_container class="space-y-4">
        <.panel>
          <:title>Profile</:title>
          <div class="flex items-center gap-3">
            <.avatar_disc user={@account} class="size-12" />
            <div>
              <p class="font-semibold">{@account.display_name}</p>
              <p class="text-sm text-base-content/60">
                Your picture comes from your linked GitHub account, or from
                <.link
                  href="https://gravatar.com"
                  class="link link-hover text-primary"
                  target="_blank"
                  rel="noopener"
                >
                  Gravatar
                </.link>
                for your notification email.
              </p>
            </div>
          </div>
        </.panel>

        <.panel>
          <:title>Sign-in providers</:title>
          <p class="text-sm text-base-content/60 mb-3">
            Any provider linked here signs you into this account. Linking one you
            have already used elsewhere brings that account's work across, and the
            last one cannot be unlinked — it is the only way back in.
          </p>

          <ul class="divide-y divide-base-300">
            <li :for={provider <- @providers} class="flex items-center gap-3 py-2">
              <span class="font-medium">{provider.label}</span>
              <.state :if={provider.identity_id} dot="bg-success" class="shrink-0">Linked</.state>
              <.link
                :if={is_nil(provider.identity_id)}
                href={~p"/settings/account/link/start/#{provider.name}"}
                class="btn btn-xs btn-ghost ml-auto"
              >
                Link account
              </.link>
              <button
                :if={provider.unlinkable?}
                type="button"
                phx-click="unlink_provider"
                phx-value-identity_id={provider.identity_id}
                data-confirm={"Unlink #{provider.label} from this account?"}
                class="btn btn-xs btn-ghost ml-auto"
              >
                Unlink
              </button>
            </li>
          </ul>
        </.panel>

        <.panel>
          <:title>Notification email</:title>
          <p class="text-sm text-base-content/60 mb-3">
            Where the CNA writes to you. You can pick any address one of your
            linked providers reported — link another provider to add to this list.
          </p>

          <.empty_state :if={@candidate_emails == []} class="py-4">
            None of your linked providers reported an email address, so there is
            nothing to choose from yet.
          </.empty_state>

          <ul :if={@candidate_emails != []} class="divide-y divide-base-300">
            <li :for={candidate <- @candidate_emails} class="flex items-center gap-3 py-2">
              <.mono_chip size={:small}>{candidate.email}</.mono_chip>
              <.state :if={candidate.in_use?} dot="bg-success" class="shrink-0">
                In use
              </.state>
              <button
                :if={!candidate.in_use?}
                type="button"
                phx-click="set_notification_email"
                phx-value-notification_email={candidate.email}
                class="btn btn-xs btn-ghost ml-auto"
              >
                Use this
              </button>
            </li>
          </ul>
        </.panel>

        <.panel>
          <:title>Sessions</:title>
          <p class="text-sm text-base-content/60 mb-3">
            Every browser you are currently signed in on. Signing one out ends it
            straight away — do that for anything you do not recognise, or for a
            computer you have stopped using.
          </p>

          <ul class="divide-y divide-base-300">
            <li :for={session <- @sessions} class="flex items-center gap-3 py-2">
              <div class="min-w-0">
                <p class="flex items-center gap-2">
                  <span class="font-medium truncate">{session.user_agent || "Unknown browser"}</span>
                  <.state :if={session.current?} dot="bg-success" class="shrink-0">
                    This device
                  </.state>
                </p>
                <p class="text-xs text-base-content/60">
                  <span :if={session.ip}>{session.ip} · </span>
                  signed in {format_datetime(session.signed_in_at)}
                </p>
              </div>
              <button
                :if={!session.current?}
                type="button"
                phx-click="revoke_session"
                phx-value-jti={session.jti}
                class="btn btn-xs btn-ghost ml-auto"
              >
                Sign out
              </button>
            </li>
          </ul>

          <button
            :if={Enum.count(@sessions, &(not &1.current?)) > 0}
            type="button"
            phx-click="revoke_other_sessions"
            data-confirm="Sign out every other session?"
            class="btn btn-sm btn-outline mt-3"
          >
            Sign out everywhere else
          </button>
        </.panel>

        <.panel class="border-error/40">
          <:title>Delete account</:title>
          <p class="text-sm text-base-content/60 mb-3">
            Your sign-in providers, API tokens and case assignments go with the
            account, and you are signed out. What you wrote stays — comments,
            suggestions and reports keep their place in the record, credited to a
            deleted user. This cannot be undone.
          </p>

          <button
            type="button"
            phx-click="delete_account"
            data-confirm="Delete your account? This cannot be undone."
            class="btn btn-sm btn-error btn-outline"
          >
            Delete my account
          </button>
        </.panel>
      </.page_container>
    </Layouts.app>
    """
  end
end
