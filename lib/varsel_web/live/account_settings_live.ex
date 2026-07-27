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

  alias Varsel.Accounts

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    {:ok, socket |> assign(page_title: "Account") |> assign_account()}
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

  defp assign_account(%{assigns: %{current_user: nil}}), do: raise(VarselWeb.UnauthorizedError)

  # The addresses to choose between are exactly what this user's providers
  # reported, deduplicated — the same address from two providers is one choice.
  defp assign_account(socket) do
    actor = socket.assigns.current_user

    account =
      Ash.load!(actor, [:avatar_url, :display_name, :identity_emails, :identities], actor: actor)

    linked = MapSet.new(account.identities, &to_string(&1.strategy))

    assign(socket,
      account: account,
      candidate_emails: candidate_emails(account),
      providers:
        Enum.map(oauth_strategies(), fn strategy ->
          %{
            name: strategy.name,
            label: provider_label(strategy.name),
            linked?: MapSet.member?(linked, to_string(strategy.name))
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

  defp provider_label(:github), do: "GitHub"
  defp provider_label(:hex), do: "Hex.pm"

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <.page_header>
      <:eyebrow>CNA Console</:eyebrow>
      <:title>Account</:title>
      <:subtitle>Your profile and how the CNA reaches you.</:subtitle>
    </.page_header>

    <.page_container class="space-y-4">
      <div class="rounded-box border border-base-300 p-4 flex items-center gap-3">
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

      <div class="rounded-box border border-base-300 p-4">
        <h2 class="font-semibold">Sign-in providers</h2>
        <p class="text-sm text-base-content/60 mt-0.5 mb-3">
          Any provider linked here signs you into this account. Linking one you
          have already used elsewhere brings that account's work across.
        </p>

        <ul class="divide-y divide-base-300">
          <li :for={provider <- @providers} class="flex items-center gap-3 py-2">
            <span class="font-medium">{provider.label}</span>
            <.state :if={provider.linked?} dot="bg-success" class="shrink-0">Linked</.state>
            <.link
              :if={!provider.linked?}
              href={~p"/settings/account/link/start/#{provider.name}"}
              class="btn btn-xs btn-ghost ml-auto"
            >
              Link account
            </.link>
          </li>
        </ul>
      </div>

      <div class="rounded-box border border-base-300 p-4">
        <h2 class="font-semibold">Notification email</h2>
        <p class="text-sm text-base-content/60 mt-0.5 mb-3">
          Where the CNA writes to you. You can pick any address one of your
          linked providers reported — link another provider to add to this list.
        </p>

        <p :if={@candidate_emails == []} class="text-sm text-base-content/60">
          None of your linked providers reported an email address, so there is
          nothing to choose from yet.
        </p>

        <ul :if={@candidate_emails != []} class="divide-y divide-base-300">
          <li :for={candidate <- @candidate_emails} class="flex items-center gap-3 py-2">
            <span class="font-mono text-sm">{candidate.email}</span>
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
      </div>
    </.page_container>
    """
  end
end
