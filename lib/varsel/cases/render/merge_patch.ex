# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Render.MergePatch do
  @moduledoc """
  RFC 7396 JSON Merge Patch — the semantics of every render escape hatch
  (`Case.cna_override`, `PackageChannel.entry_override`).

  Objects merge recursively; `nil` deletes a key; anything else (including
  arrays) replaces the target value wholesale.
  """

  @doc "Applies an RFC 7396 merge patch to a value. A nil patch is a no-op."
  @spec apply(term(), term() | nil) :: term()
  def apply(target, nil), do: target

  def apply(target, patch) when is_map(patch) do
    target = if is_map(target), do: target, else: %{}

    Enum.reduce(patch, target, fn
      {key, nil}, acc -> Map.delete(acc, key)
      {key, value}, acc -> Map.put(acc, key, __MODULE__.apply(Map.get(acc, key), value))
    end)
  end

  def apply(_target, patch), do: patch
end
