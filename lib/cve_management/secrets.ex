# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Secrets do
  @moduledoc false
  use AshAuthentication.Secret

  alias CveManagement.Accounts.User

  def secret_for([:authentication, :tokens, :signing_secret], User, _opts, _context) do
    Application.fetch_env(:cve_management, :token_signing_secret)
  end

  def secret_for([:authentication, :strategies, :github, :client_id], User, _opts, _context) do
    get_github_config(:client_id)
  end

  def secret_for([:authentication, :strategies, :github, :redirect_uri], User, _opts, _context) do
    get_github_config(:redirect_uri)
  end

  def secret_for([:authentication, :strategies, :github, :client_secret], User, _opts, _context) do
    get_github_config(:client_secret)
  end

  defp get_github_config(key) do
    :cve_management
    |> Application.get_env(:github, [])
    |> Keyword.fetch(key)
  end
end
