# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.JSON do
  @moduledoc """
  JSON decoding that takes either a whole binary or a stream of chunks.
  """

  # Elixir's `JSON` passes the same mapping; `:json`'s own default is `:null`.
  @decoders %{null: nil}

  @doc """
  Decodes a JSON document given whole or as a stream of binary chunks.
  """
  @spec decode!(binary() | Enumerable.t(binary())) :: term()
  def decode!(json) when is_binary(json), do: JSON.decode!(json)

  def decode!(chunks) do
    chunks
    |> Enum.reduce(:json.decode_start("", :ok, @decoders), &decode_chunk/2)
    |> finish()
  end

  defp decode_chunk(chunk, {:continue, state}) do
    :json.decode_continue(chunk, state)
  rescue
    e in ErlangError -> reraise decode_error(e.original, chunk), __STACKTRACE__
  end

  defp decode_chunk(_chunk, decoded), do: decoded

  defp finish({:continue, state}) do
    {term, :ok, _rest} = :json.decode_continue(:end_of_input, state)
    term
  rescue
    e in ErlangError -> reraise decode_error(e.original, ""), __STACKTRACE__
  end

  defp finish({term, :ok, _rest}), do: term

  # `:json` reports only the offending byte, so locate it in the chunk to give
  # the same fields Elixir's `JSON` reports for a whole binary.
  defp decode_error({:invalid_byte, byte}, data) do
    offset =
      data
      |> :binary.match(<<byte>>)
      |> case do
        {offset, _length} -> offset
        :nomatch -> 0
      end

    %JSON.DecodeError{
      message: "invalid byte #{byte} at position (byte offset) #{offset}",
      data: data,
      offset: offset
    }
  end

  defp decode_error(:unexpected_end, data) do
    %JSON.DecodeError{
      message: "unexpected end of JSON binary at position (byte offset) #{byte_size(data)}",
      data: data,
      offset: byte_size(data)
    }
  end
end
