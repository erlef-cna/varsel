# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Validations.AdvisoryUrl do
  @moduledoc """
  Takes an `advisory_url` only when it names a GitHub advisory. An absent
  one passes, and `allow_nil?` on the argument decides whether it may be.

  With `repository?: true` the advisory must be on a repository. A global
  database entry is read with the CNA's own token
  (`Varsel.GitHub.Credentials.public_read/0`), so reading it proves nothing
  about the caller.
  """

  use Ash.Resource.Validation

  alias Ash.Changeset
  alias Ash.Resource.Validation
  alias Varsel.GitHub.Advisories

  @impl Validation
  def init(opts) do
    if is_boolean(Keyword.get(opts, :repository?, false)) do
      {:ok, opts}
    else
      {:error, "`repository?` must be a boolean"}
    end
  end

  @impl Validation
  def validate(changeset, opts, _context) do
    case Changeset.get_argument(changeset, :advisory_url) do
      nil ->
        :ok

      url when is_binary(url) ->
        url |> Advisories.parse() |> check(Keyword.get(opts, :repository?, false))
    end
  end

  defp check({:ok, %{owner: owner, repo: repo}}, _repository?) when is_binary(owner) and is_binary(repo), do: :ok

  defp check({:ok, _global}, false), do: :ok

  defp check({:ok, _global}, true) do
    {:error,
     field: :advisory_url,
     message:
       "must be the advisory's address on its repository, such as https://github.com/owner/repo/security/advisories/GHSA-…"}
  end

  defp check(:error, _repository?) do
    {:error, field: :advisory_url, message: "is not a GitHub advisory URL or GHSA id"}
  end
end
