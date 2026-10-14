# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Errors.NotInstalled do
  @moduledoc """
  The GitHub App has no installation to mint a token for: the App is not
  configured, no home organization is configured, or the App is not
  installed on the account.
  """

  use Splode.Error, fields: [:account], class: :invalid

  @impl Exception
  def message(%{account: nil}), do: "The GitHub App has no home organization installation"
  def message(%{account: account}), do: "The GitHub App is not installed on #{account}"
end
