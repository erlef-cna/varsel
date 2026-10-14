# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Errors.RefreshFailed do
  @moduledoc """
  GitHub answered the refresh of an identity's access token with an OAuth
  error that is not a refusal of the refresh token, such as
  `incorrect_client_credentials`. `description` is GitHub's
  `error_description`, when it sent one.
  """

  use Splode.Error, fields: [:error, :description], class: :unknown

  @impl Exception
  def message(%{error: error, description: nil}), do: "GitHub did not refresh the access token (#{error})"

  def message(%{error: error, description: description}),
    do: "GitHub did not refresh the access token (#{error}: #{description})"
end
