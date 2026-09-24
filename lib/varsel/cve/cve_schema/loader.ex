# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveSchema.Loader do
  @moduledoc """
  Reads the vendored CVE schema files from `priv/cve_schema`.

  `Varsel.CVE.CveSchema` resolves its schema at compile time, which cannot call
  its own functions. This module holds the file access so both the compile-time
  resolution and the `ex_json_schema` remote resolver can reach it.
  """

  @doc """
  Resolves `file:` schema references against the vendored schema directory.

  Configured in `config.exs` as the `ex_json_schema` remote schema resolver.
  """
  @spec resolve_ref(String.t()) :: map()
  def resolve_ref("file:" <> path), do: load!(path)

  def resolve_ref(url) do
    raise "refusing to resolve non-vendored schema reference: #{inspect(url)}"
  end

  @doc """
  Reads and decodes one vendored schema file, relative to `priv/cve_schema`.
  """
  @spec load!(String.t()) :: map()
  # sobelow_skip ["Traversal.FileModule"]
  def load!(path) do
    priv_dir = dir()
    {:ok, path} = Path.safe_relative(path, priv_dir)

    priv_dir
    |> Path.join(path)
    |> File.read!()
    |> JSON.decode!()
  end

  @doc """
  Lists every vendored schema file, for `@external_resource` tracking.
  """
  @spec files() :: [String.t()]
  def files, do: Path.wildcard(Path.join([dir(), "**", "*.json"]))

  defp dir, do: Path.join(:code.priv_dir(:varsel), "cve_schema")
end
