# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.People do
  @moduledoc """
  A case's credits as GitHub sees people. GitHub knows a person by login and
  gives each person one role. A case credits a person by name, with every
  role they carry and a GitHub handle where they have one. This module
  gathers either side's credits per person, so
  `Varsel.Cases.GitHubAdvisory.Export` and `Varsel.Cases.GitHubAdvisory.Diff`
  speak of the same people.
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
      key = person_key(credit)

      case List.keyfind(people, key, 0) do
        nil ->
          [{key, %{login: login, name: name, roles: credit.credit_types}} | people]

        {^key, person} ->
          List.keyreplace(
            people,
            key,
            0,
            {key, %{person | roles: person.roles ++ credit.credit_types}}
          )
      end
    end)
    |> Enum.reverse()
    |> Enum.map(fn {_key, person} -> %{person | roles: Enum.uniq(person.roles)} end)
  end

  @doc """
  What identifies the person a credit names on either side: the GitHub login
  where the case knows it, and the name otherwise. Compared
  case-insensitively.
  """
  @spec person_key(map()) :: String.t()
  def person_key(credit) do
    case identity(credit) do
      {nil, name} -> "name:" <> String.downcase(name)
      {login, _name} -> login
    end
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
