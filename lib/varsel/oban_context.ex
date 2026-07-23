# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.ObanContext do
  @moduledoc """
  Forwards an enclosing action's scope to the nested Ash calls it makes.

  Generic actions (`run fn`) and changes often call `Ash.read!/create!/…`
  internally. Those nested calls start with an empty scope, so without help
  they neither carry the actor nor the `ash_oban?: true` flag that lets an
  AshOban-run action clear an `AshObanInteraction` bypass.

  `forward/2` builds the option list for a nested call from the outer
  `context`: it takes actor/tenant/tracer/authorize? via `Ash.Context.to_opts`
  and re-adds the `ash_oban?` private flag that `to_opts` drops — but only when
  the outer context actually carries it (i.e. we are genuinely inside an Oban
  run). It never fabricates the flag, so it can't become a blanket
  authorization bypass. Caller-supplied `opts` win over the forwarded ones.
  """

  @doc """
  Options for a nested Ash call, forwarding `context`'s scope and merging
  `opts` on top.
  """
  @spec forward(map(), keyword()) :: keyword()
  def forward(context, opts \\ []) do
    context
    |> Ash.Context.to_opts()
    |> maybe_put_oban(context)
    |> Keyword.merge(opts)
  end

  # Sets the flag under `:private` so the AshObanInteraction bypass matches the
  # nested call itself.
  @oban_context %{private: %{ash_oban?: true}}

  defp maybe_put_oban(base, context) do
    if get_in(Map.get(context, :source_context) || %{}, [:private, :ash_oban?]) do
      Keyword.update(base, :context, @oban_context, fn existing ->
        Ash.Helpers.deep_merge_maps(existing, @oban_context)
      end)
    else
      base
    end
  end
end
