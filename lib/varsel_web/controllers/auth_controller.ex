# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AuthController do
  use VarselWeb, :controller
  use AshAuthentication.Phoenix.Controller

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Strategy.OAuth2.UserResolver
  alias Varsel.Accounts.User.Changes.ResolveOauthIdentity
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

        _ ->
          # A refusal from the OAuth callback arrives wrapped: the register
          # action's error is re-raised as `AuthenticationFailed` by
          # `OAuth2.Actions.register/3`, so the one that says *why* is nested
          # inside it. Search rather than match a fixed depth.
          oauth_refusal(reason) || "Incorrect email or password"
      end

    # A failed link is not a failed sign-in: the caller is still signed in as
    # whoever they were, and belongs back where they started.
    linking? = not is_nil(get_session(conn, OauthLinking.session_key()))

    conn
    # A link that failed is over; the next sign-in must not inherit it.
    |> delete_session(OauthLinking.session_key())
    |> put_flash(:error, message)
    |> redirect(to: if(linking?, do: ~p"/settings/account", else: ~p"/sign-in"))
  end

  # The sentence to show for an OAuth refusal, or nil if this was not one.
  # Both cases are a deliberate refusal with something specific to say; the
  # generic fallback would tell the caller their password was wrong, when no
  # password was involved.
  defp oauth_refusal(%{caused_by: %{module: ResolveOauthIdentity, message: message}}), do: message

  defp oauth_refusal(%{caused_by: %{module: UserResolver, message: "Email could not be" <> _}}) do
    """
    An account here already uses that email address. Sign in with the \
    provider you first used, then link this one from your account page.
    """
  end

  defp oauth_refusal(%{caused_by: caused_by}), do: oauth_refusal(caused_by)

  defp oauth_refusal(%{errors: errors}) when is_list(errors), do: Enum.find_value(errors, &oauth_refusal/1)

  defp oauth_refusal(_reason), do: nil

  def sign_out(conn, _params) do
    return_to = get_session(conn, :return_to) || ~p"/"

    conn
    |> clear_session(:varsel)
    |> put_flash(:info, "You are now signed out")
    |> redirect(to: return_to)
  end
end
