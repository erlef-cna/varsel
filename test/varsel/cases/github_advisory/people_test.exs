# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.PeopleTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseCredit.Handle
  alias Varsel.Cases.GitHubAdvisory.People

  defp credit(name, type, handles \\ []) do
    %CaseCredit{name: name, credit_types: List.wrap(type), handles: handles}
  end

  defp github(username), do: %Handle{strategy: :github, username: username}

  test "people/1 gathers a case's credits per GitHub login, then per name" do
    credits = [
      credit("Lukas", [:analyst, :coordinator], [github("garazdawi")]),
      credit("Lukas L.", :reporter, [github("GARAZDAWI")]),
      credit("Nobody Here", :finder),
      credit("nobody here", :finder),
      credit("Alice", :sponsor, [%Handle{strategy: :hex, username: "alice"}])
    ]

    assert People.people(credits) == [
             %{login: "garazdawi", name: "Lukas", roles: [:analyst, :coordinator, :reporter]},
             %{login: nil, name: "Nobody Here", roles: [:finder]},
             %{login: nil, name: "Alice", roles: [:sponsor]}
           ]
  end

  test "people/1 gathers an advisory's credits by login, named as the login" do
    credits = [
      %{login: "Alice", credit_types: [:finder]},
      %{login: "alice", credit_types: [:analyst]}
    ]

    assert People.people(credits) == [
             %{login: "alice", name: "Alice", roles: [:finder, :analyst]}
           ]
  end

  test "person_key/1 is the GitHub login, else the name, case-insensitively" do
    assert People.person_key(credit("Lukas", :reporter, [github("Garazdawi")])) == "garazdawi"
    assert People.person_key(credit("Nobody Here", :finder)) == "name:nobody here"
    assert People.person_key(%{login: "Alice", credit_types: [:finder]}) == "alice"
  end

  test "github_handle/1 finds the GitHub handle among a credit's handles" do
    assert People.github_handle(credit("A", :finder, [%Handle{strategy: :hex, username: "a"}, github("A")])) == "A"

    assert People.github_handle(credit("A", :finder)) == nil
    assert People.github_handle(%{login: "a"}) == nil
  end
end
