# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequest.Checks.TokenMatches do
  @moduledoc """
  Whether the `token` argument is the request's own one-time token. This is
  the whole authorization of the two steps that the command runs: whoever
  holds the token acts for the request.

  The token must verify as an AshAuthentication token of
  `Varsel.Accounts.User` (signature, expiry, issuer, audience), carry the
  purpose `github_manual`, name the request's user as its subject and the
  request as its `request_id`, still be stored with that purpose, and not be
  revoked.
  """

  use Ash.Policy.SimpleCheck

  alias Ash.Changeset
  alias AshAuthentication.Jwt
  alias AshAuthentication.TokenResource
  alias Varsel.Accounts.Token
  alias Varsel.Accounts.User

  @purpose "github_manual"

  @impl Ash.Policy.Check
  def describe(_opts), do: "the token is the request's own github_manual token"

  @impl Ash.Policy.SimpleCheck
  def match?(_actor, %{subject: %Changeset{data: request} = changeset}, _opts) do
    token = Changeset.get_argument(changeset, :token)
    subject = AshAuthentication.user_to_subject(%User{id: request.user_id})
    request_id = request.id

    with true <- is_binary(token),
         {:ok, %{"purpose" => @purpose, "sub" => ^subject, "request_id" => ^request_id}, User} <-
           Jwt.verify(token, User),
         {:ok, [%{purpose: @purpose}]} <-
           TokenResource.Actions.get_token(Token, %{"token" => token, "purpose" => @purpose}) do
      not TokenResource.Actions.token_revoked?(Token, token)
    else
      _refused -> false
    end
  end

  def match?(_actor, _context, _opts), do: false
end
