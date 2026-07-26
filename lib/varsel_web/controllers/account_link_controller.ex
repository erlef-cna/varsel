# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AccountLinkController do
  @moduledoc """
  Starts and finishes linking a second provider to an account.

  The OAuth callback cannot tell "link this to the account I am already signed
  in as" from "sign me in" — it registers either way. So `start/2` remembers
  who asked before handing off to the provider, and `AuthController.success/4`
  reads that marker to divert to a confirmation page instead of completing an
  ordinary sign-in.
  """

  use VarselWeb, :controller

  import AshAuthentication.Plug.Helpers, only: [store_in_session: 2]

  alias Varsel.Accounts

  @session_key :linking_from_user_id

  @doc "The session key holding the account a link was started from."
  @spec session_key() :: atom()
  def session_key, do: @session_key

  @doc """
  Remembers the current account, then sends the browser to the provider.
  """
  def start(conn, %{"strategy" => strategy}) do
    conn
    |> put_session(@session_key, conn.assigns.current_user.id)
    |> redirect(to: "/auth/user/#{strategy}")
  end

  @doc """
  Asks whether to link, naming both accounts. Reached from
  `AuthController.success/4` when a sign-in completes during a link.
  """
  def confirm_page(conn, _params) do
    signed_in = conn.assigns.current_user

    case get_session(conn, @session_key) do
      nil ->
        redirect(conn, to: ~p"/settings/account")

      linking_from_id ->
        render(conn, :confirm,
          signed_in: Ash.load!(signed_in, [:display_name], actor: signed_in),
          linking_from:
            Accounts.get_link_counterpart!(linking_from_id,
              actor: signed_in,
              load: [:display_name]
            )
        )
    end
  end

  @doc """
  Confirms the link: the account just signed in as is merged into the one the
  link was started from, handing over its providers and any live work.
  """
  def confirm(conn, _params) do
    signed_in = conn.assigns.current_user

    case Accounts.merge_user_into(signed_in, get_session(conn, @session_key), actor: signed_in) do
      {:ok, _merged} ->
        keep = Accounts.get_link_counterpart!(get_session(conn, @session_key), actor: signed_in)

        conn
        |> delete_session(@session_key)
        # The session was holding the account that just merged away, so it has
        # to move to the surviving one — signing the caller in as it.
        |> store_in_session(with_session_token(keep))
        |> assign(:current_user, keep)
        |> put_flash(:info, "Provider linked to your account.")
        |> redirect(to: ~p"/settings/account")

      {:error, _error} ->
        conn
        |> delete_session(@session_key)
        |> put_flash(:error, "Could not link that provider to your account.")
        |> redirect(to: ~p"/settings/account")
    end
  end

  @doc """
  Declines the link, leaving the new account standing and the session on it —
  the sign-in already happened, and it was a real one.
  """
  def decline(conn, _params) do
    conn
    |> delete_session(@session_key)
    |> put_flash(:info, "Kept as a separate account. You are signed in as it.")
    |> redirect(to: ~p"/settings/account")
  end

  # `store_in_session/2` reads the token from the record's metadata, and this
  # app requires one to be present and stored.
  defp with_session_token(user) do
    {:ok, token, _claims} = AshAuthentication.Jwt.token_for_user(user)
    Ash.Resource.put_metadata(user, :token, token)
  end
end
