# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.HandleLookup do
  @moduledoc """
  Confirms a provider handle and reports what the provider says about the
  account: the spelling it uses, the person's name, and their address.

  hex.pm answers through its contact endpoint when Varsel holds a signing
  key for it, and through the public profile otherwise.
  """

  alias Varsel.Accounts.GitHub
  alias Varsel.Cases.CaseInvite.Strategy
  alias Varsel.HexPm

  @typedoc """
  An account as its provider reports it. `name` and `email` are `nil` when
  the provider lists none.
  """
  @type account :: %{username: String.t(), name: String.t() | nil, email: String.t() | nil}

  @doc "Confirms that the handle names an account at its provider."
  @spec confirm(Strategy.t(), String.t()) :: {:ok, account()} | {:error, String.t()}
  def confirm(:github, username) do
    case GitHub.user(username) do
      {:ok, %{login: canonical, name: name, email: email}} ->
        {:ok, %{username: canonical, name: name, email: email}}

      :not_found ->
        {:error, "is not a GitHub account"}
    end
  end

  def confirm(:hex, username) do
    case HexPm.contact(username) do
      {:ok, %{username: canonical, name: name, email: email}} ->
        {:ok, %{username: canonical, name: name, email: email}}

      :not_found ->
        {:error, "is not a hex.pm account"}

      {:error, :not_configured} ->
        profile(username)

      {:error, _reason} ->
        {:error, "could not be looked up at hex.pm"}
    end
  end

  @doc "The provider's name for people."
  @spec provider_name(Strategy.t()) :: String.t()
  def provider_name(:github), do: "GitHub"
  def provider_name(:hex), do: "hex.pm"

  defp profile(username) do
    case HexPm.user(username) do
      {:ok, %{username: canonical, name: name, email: email}} ->
        {:ok, %{username: canonical, name: name, email: email}}

      :not_found ->
        {:error, "is not a hex.pm account"}
    end
  end
end
