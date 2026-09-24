# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveSchema do
  @moduledoc """
  Validates CVE records against the official CVE JSON record schema.

  The schema (`CVE_Record_Format.json` plus the CVSS/tag files it references) is
  vendored under `priv/cve_schema`, mirroring
  https://github.com/CVEProject/cve-schema. `file:` references inside the schema
  are resolved against that directory by `Varsel.CVE.CveSchema.Loader`, which is
  configured as `ex_json_schema`'s remote schema resolver.
  """

  alias Varsel.CVE.CveSchema.Loader

  @doc """
  Validates a decoded CVE record map against the CVE record schema.

  Returns `:ok` or `{:error, [{message, json_path}]}`.
  """
  @spec validate(map()) :: :ok | {:error, [{String.t(), String.t()}]}
  def validate(record) when is_map(record) do
    ExJsonSchema.Validator.validate(schema(), record)
  end

  for path <- Loader.files() do
    @external_resource path
  end

  @schema "CVE_Record_Format.json" |> Loader.load!() |> ExJsonSchema.Schema.resolve()

  defp schema, do: @schema
end
