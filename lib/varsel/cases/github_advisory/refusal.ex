# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Refusal do
  @moduledoc """
  The sentence an action answers with, after its subject, when a write to
  GitHub was refused or GitHub could not be reached.
  """

  alias Varsel.GitHub.UserToken

  @doc """
  The sentence for `answer`, a `Varsel.GitHub.Advisories` result that is not
  `{:ok, _}`. `not_found` is the sentence for `:not_found`, which each action
  states in its own terms.
  """
  @spec message(:not_found | {:error, term()}, String.t()) :: String.t()
  def message(:not_found, not_found), do: not_found

  def message({:error, :unauthorized}, _not_found), do: UserToken.message(:unauthorized)

  def message({:error, {:http, _status, %{"message" => message}}}, _not_found) when is_binary(message),
    do: "was refused by GitHub: #{message}"

  def message({:error, {:http, status, _body}}, _not_found), do: "was refused by GitHub (HTTP #{status})"

  def message({:error, _reason}, _not_found), do: "could not reach GitHub"
end
