# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Errors.GitHubUnreachable do
  @moduledoc """
  The refresh of an identity's access token did not reach GitHub.
  """

  use Splode.Error, fields: [:reason], class: :unknown

  @impl Exception
  def message(%{reason: reason}), do: "GitHub could not be reached to refresh the access token (#{inspect(reason)})"
end
