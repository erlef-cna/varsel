# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveSchema do
  @moduledoc """
  Validates CVE records against the official CVE JSON record schema.

  The schema (`CVE_Record_Format.json` plus the CVSS/tag files it references) is
  vendored under `priv/cve_schema`, mirroring
  https://github.com/CVEProject/cve-schema. `file:` references inside the schema
  are resolved against that directory via `resolve_ref/1`, which is configured as
  `ex_json_schema`'s remote schema resolver.
  """

  @persistent_term_key {__MODULE__, :schema}

  @doc """
  Validates a decoded CVE record map against the CVE record schema.

  Returns `:ok` or `{:error, [{message, json_path}]}`.
  """
  @spec validate(map()) :: :ok | {:error, [{String.t(), String.t()}]}
  def validate(record) when is_map(record) do
    ExJsonSchema.Validator.validate(schema(), record)
  end

  @doc """
  Resolves `file:` schema references against the vendored schema directory.

  Configured in `config.exs` as the `ex_json_schema` remote schema resolver.
  """
  @spec resolve_ref(String.t()) :: map()
  def resolve_ref("file:" <> path), do: load_schema_file!(path)

  def resolve_ref(url) do
    raise "refusing to resolve non-vendored schema reference: #{inspect(url)}"
  end

  defp schema do
    case :persistent_term.get(@persistent_term_key, nil) do
      nil ->
        schema =
          "CVE_Record_Format.json"
          |> load_schema_file!()
          |> ExJsonSchema.Schema.resolve()

        :persistent_term.put(@persistent_term_key, schema)
        schema

      schema ->
        schema
    end
  end

  # sobelow_skip ["Traversal.FileModule"]
  defp load_schema_file!(path) do
    priv_dir = Path.join(:code.priv_dir(:varsel), "cve_schema")
    {:ok, path} = Path.safe_relative(path, priv_dir)

    priv_dir
    |> Path.join(path)
    |> File.read!()
    |> JSON.decode!()
  end
end
