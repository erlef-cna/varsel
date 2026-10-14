# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Errors.RefreshRefused do
  @moduledoc """
  GitHub did not exchange the identity's refresh token for a new access
  token: the identity has no refresh token, or GitHub refused the one it has.
  Only a new sign-in gives the identity a usable token again.
  """

  use Splode.Error, fields: [:reason], class: :forbidden

  @impl Exception
  def message(%{reason: reason}), do: "GitHub refused to refresh the access token (#{reason})"
end
