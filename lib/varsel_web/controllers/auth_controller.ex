# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AuthController do
  use VarselWeb, :controller
  use AshAuthentication.Phoenix.Controller

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Strategy.OAuth2.UserResolver
  alias VarselWeb.AccountLinkController

  def success(conn, activity, user, _token) do
    return_to = get_session(conn, :return_to) || ~p"/"

    message =
      case activity do
        {:confirm_new_user, :confirm} -> "Your email address has now been confirmed"
        {:password, :reset} -> "Your password has successfully been reset"
        _ -> "You are now signed in"
      end

    conn =
      conn
      |> delete_session(:return_to)
      |> store_in_session(user)
      # If your resource has a different name, update the assign name here (i.e :current_admin)
      |> assign(:current_user, user)

    # A sign-in that began as a link is still a real sign-in — the session is
    # stored either way, so declining leaves the caller on the account they
    # just proved they hold. Only the destination differs.
    if get_session(conn, AccountLinkController.session_key()) do
      redirect(conn, to: ~p"/settings/account/link/confirm")
    else
      conn
      |> put_flash(:info, message)
      |> redirect(to: return_to)
    end
  end

  def failure(conn, activity, reason) do
    message =
      case {activity, reason} do
        {_,
         %AuthenticationFailed{
           caused_by: %Ash.Error.Forbidden{
             errors: [%AshAuthentication.Errors.CannotConfirmUnconfirmedUser{}]
           }
         }} ->
          """
          You have already signed in another way, but have not confirmed your account.
          You can confirm your account using the link we sent to you, or by resetting your password.
          """

        # An account already holds this address. We will not take a provider's
        # word for who owns an email, so the way in is to sign in as whoever
        # that account already is, and link this provider from there.
        {_,
         %AuthenticationFailed{
           caused_by: %{module: UserResolver, message: "Email could not be verified" <> _}
         }} ->
          """
          An account here already uses that email address. Sign in with the \
          provider you first used, then link this one from your account page.
          """

        _ ->
          "Incorrect email or password"
      end

    conn
    |> put_flash(:error, message)
    |> redirect(to: ~p"/sign-in")
  end

  def sign_out(conn, _params) do
    return_to = get_session(conn, :return_to) || ~p"/"

    conn
    |> clear_session(:varsel)
    |> put_flash(:info, "You are now signed out")
    |> redirect(to: return_to)
  end
end
