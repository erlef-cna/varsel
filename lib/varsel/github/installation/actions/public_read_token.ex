# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation.Actions.PublicReadToken do
  @moduledoc """
  Runs `Varsel.GitHub.Installation`'s `:public_read_token` action.

  Anyone may call the action, so the caller has no actor that the
  installation policies accept. The lookup and the mint run as the
  `Varsel.Service.github_public_read/0` actor instead.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.GitHub
  alias Varsel.GitHub.App
  alias Varsel.GitHub.Errors.NotInstalled
  alias Varsel.GitHub.Installation
  alias Varsel.GitHub.Installation.Mint
  alias Varsel.GitHub.Sync

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    opts = context |> Map.put(:actor, Varsel.Service.github_public_read()) |> Sync.opts()

    with {:ok, account} <- home_org(),
         {:ok, %Installation{id: id}} <- installation(account, opts) do
      Mint.token(id, opts)
    end
  end

  defp home_org do
    case App.home_org() do
      nil -> {:error, NotInstalled.exception(account: nil)}
      account -> {:ok, account}
    end
  end

  defp installation(account, opts) do
    case GitHub.installation_for_account(account, opts) do
      {:ok, nil} -> {:error, NotInstalled.exception(account: account)}
      other -> other
    end
  end
end
