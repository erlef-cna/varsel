# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.StubResolver do
  @moduledoc """
  Test double for the DNS lookup `Varsel.Cases.Derivation.PinnedTransport`
  performs.

  Tests declare what a host answers with:

      StubResolver.stub(%{"forge.example" => [{140, 82, 121, 3}]})

  A host can also be given a *queue* of answers, one per lookup, which is how
  a rebinding host is expressed — public when the URL was saved, private when
  the clone happens:

      StubResolver.stub(%{"rebind.example" => [[{93, 184, 216, 34}], [{127, 0, 0, 1}]]})

  Unlisted hosts answer `{:error, :nxdomain}`.
  """

  @key {__MODULE__, :answers}

  @spec stub(%{String.t() => [tuple()] | [[tuple()]]}) :: :ok
  def stub(answers) do
    :persistent_term.put(@key, answers)
    :ok
  end

  @spec clear() :: :ok
  def clear do
    :persistent_term.erase(@key)
    :ok
  end

  @doc "Matches `:inet.getaddrs/2`."
  @spec getaddrs(charlist(), :inet | :inet6) :: {:ok, [tuple()]} | {:error, atom()}
  def getaddrs(charlist, family) do
    host = to_string(charlist)

    case @key |> :persistent_term.get(%{}) |> Map.fetch(host) do
      {:ok, answers} -> answer(host, answers, family)
      :error -> {:error, :nxdomain}
    end
  end

  # A queue (list of lists) hands out its head and keeps the rest for the next
  # lookup, so consecutive calls can disagree. A flat list always answers the
  # same. Both are v4-only, so the v6 pass adds nothing.
  defp answer(_host, _answers, :inet6), do: {:error, :nxdomain}

  defp answer(host, [[_ | _] | _] = queue, :inet) do
    [current | rest] = queue
    answers = :persistent_term.get(@key, %{})
    :persistent_term.put(@key, Map.put(answers, host, rest_or_last(rest, current)))
    {:ok, current}
  end

  defp answer(_host, addresses, :inet), do: {:ok, addresses}

  # The last answer in a queue sticks, so a test need not count lookups.
  defp rest_or_last([], current), do: [current]
  defp rest_or_last(rest, _current), do: rest
end
