# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.PeopleTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseCredit.Handle
  alias Varsel.Cases.GitHubAdvisory.People

  defp credit(name, type, handles \\ []) do
    %CaseCredit{name: name, credit_type: type, handles: handles}
  end

  defp github(username), do: %Handle{strategy: :github, username: username}

  test "people/1 gathers a case's credits per GitHub login, then per name" do
    credits = [
      credit("Lukas", :analyst, [github("garazdawi")]),
      credit("Lukas L.", :reporter, [github("GARAZDAWI")]),
      credit("Nobody Here", :finder),
      credit("nobody here", :finder),
      credit("Alice", :sponsor, [%Handle{strategy: :hex, username: "alice"}])
    ]

    assert People.people(credits) == [
             %{login: "garazdawi", name: "Lukas", roles: [:analyst, :reporter]},
             %{login: nil, name: "Nobody Here", roles: [:finder]},
             %{login: nil, name: "Alice", roles: [:sponsor]}
           ]
  end

  test "people/1 gathers an advisory's credits by login, named as the login" do
    credits = [
      %{login: "Alice", credit_type: :finder, position: 0},
      %{login: "alice", credit_type: :analyst, position: 1}
    ]

    assert People.people(credits) == [
             %{login: "alice", name: "Alice", roles: [:finder, :analyst]}
           ]
  end

  test "credit_key/1 is the person and the role, case-insensitively" do
    assert People.credit_key(credit("Lukas", :reporter, [github("Garazdawi")])) ==
             {"garazdawi", :reporter}

    assert People.credit_key(credit("Nobody Here", :finder)) == {"nobody here", :finder}
    assert People.credit_key(%{login: "Alice", credit_type: :finder}) == {"alice", :finder}
  end

  test "github_handle/1 finds the GitHub handle among a credit's handles" do
    assert People.github_handle(credit("A", :finder, [%Handle{strategy: :hex, username: "a"}, github("A")])) == "A"

    assert People.github_handle(credit("A", :finder)) == nil
    assert People.github_handle(%{login: "a"}) == nil
  end
end
