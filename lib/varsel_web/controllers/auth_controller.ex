# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AuthController do
  use VarselWeb, :controller
  use AshAuthentication.Phoenix.Controller

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Strategy.OAuth2.UserResolver
  alias Varsel.Accounts.Strategy.LinkableOauth2
  alias VarselWeb.Plugs.OauthLinking

  def success(conn, activity, user, _token) do
    return_to = get_session(conn, :return_to) || ~p"/"

    message =
      case activity do
        {:confirm_new_user, :confirm} -> "Your email address has now been confirmed"
        {:password, :reset} -> "Your password has successfully been reset"
        _ -> "You are now signed in"
      end

    linking? = not is_nil(get_session(conn, OauthLinking.session_key()))

    conn
    |> delete_session(:return_to)
    # The marker has done its work by now: the register action attached the
    # provider to the account it named. Leaving it set would make the next
    # ordinary sign-in look like a link.
    |> delete_session(OauthLinking.session_key())
    |> store_in_session(user)
    # If your resource has a different name, update the assign name here (i.e :current_admin)
    |> assign(:current_user, user)
    |> put_flash(:info, if(linking?, do: "Provider linked to your account", else: message))
    |> redirect(to: if(linking?, do: ~p"/settings/account", else: return_to))
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

        # Mid-link, the provider account turned out to sign in to someone else.
        {_,
         %AuthenticationFailed{
           caused_by: %{module: LinkableOauth2.Actions, message: message}
         }} ->
          message

        _ ->
          "Incorrect email or password"
      end

    linking? = not is_nil(get_session(conn, OauthLinking.session_key()))

    conn
    # A link that failed is over; the next sign-in must not inherit it.
    |> delete_session(OauthLinking.session_key())
    |> put_flash(:error, message)
    |> redirect(to: if(linking?, do: ~p"/settings/account", else: ~p"/sign-in"))
  end

  def sign_out(conn, _params) do
    return_to = get_session(conn, :return_to) || ~p"/"

    conn
    |> clear_session(:varsel)
    |> put_flash(:info, "You are now signed out")
    |> redirect(to: return_to)
  end
end
