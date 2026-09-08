# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.People do
  @moduledoc """
  A case's credits as GitHub sees people. GitHub knows a person by login and
  gives each person one role. A case credits a person once per role, by name,
  with a GitHub handle where they have one. This module gathers either side's
  credits per person, so `Varsel.Cases.GitHubAdvisory.Export` and
  `Varsel.Cases.GitHubAdvisory.Diff` speak of the same people.
  """

  @type person :: %{login: String.t() | nil, name: String.t(), roles: [atom()]}

  @doc """
  The credits of either side gathered per person, in first-credit order:
  `login` (downcased, nil for a person the case knows by name alone), the
  `name` shown for them, and every `role` they carry.
  """
  @spec people([map()]) :: [person()]
  def people(credits) do
    credits
    |> Enum.reduce([], fn credit, people ->
      {login, name} = identity(credit)
      key = login || "name:" <> String.downcase(name)

      case List.keyfind(people, key, 0) do
        nil ->
          [{key, %{login: login, name: name, roles: [credit.credit_type]}} | people]

        {^key, person} ->
          List.keyreplace(
            people,
            key,
            0,
            {key, %{person | roles: person.roles ++ [credit.credit_type]}}
          )
      end
    end)
    |> Enum.reverse()
    |> Enum.map(fn {_key, person} -> %{person | roles: Enum.uniq(person.roles)} end)
  end

  @doc """
  What identifies a credit on either side: the credited person, by GitHub
  login where the case knows it and by name otherwise, with the role they
  carry. Compared case-insensitively.
  """
  @spec credit_key(map()) :: {String.t(), atom()}
  def credit_key(%{credit_type: type} = credit) do
    {login, name} = identity(credit)
    {login || String.downcase(name), type}
  end

  @doc "The GitHub login a case credit carries among its handles, or nil."
  @spec github_handle(map()) :: String.t() | nil
  def github_handle(credit) do
    credit
    |> Map.get(:handles)
    |> List.wrap()
    |> Enum.find_value(fn
      %{strategy: :github, username: username} -> to_string(username)
      _other -> nil
    end)
  end

  defp identity(%{login: login} = credit) when is_binary(login),
    do: {String.downcase(login), Map.get(credit, :name, login)}

  defp identity(%{name: name} = credit) do
    case github_handle(credit) do
      nil -> {nil, name}
      login -> {String.downcase(login), name}
    end
  end
end
