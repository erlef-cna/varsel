# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Types.CVSS do
  @moduledoc """
  Custom Ash type for CVSS vectors.

  Accepts a vector string, parses it with the `:cvss` library, and stores
  `%{vector: string, version: atom, score: float, severity: atom}` in the DB.

  Supports an optional `version` constraint to restrict which CVSS versions
  are accepted, e.g. `constraints: [version: [:v3, :v4]]`.
  """

  @behaviour AshGraphql.Type

  use Ash.Type

  @enforce_keys [:vector, :version, :score, :severity]
  defstruct [:vector, :version, :score, :severity]

  @versions [:v1, :v2, :v3, :v4]

  @type t :: %__MODULE__{
          vector: String.t(),
          version: :v1 | :v2 | :v3 | :v4,
          score: float(),
          severity: atom() | nil
        }

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :json

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :string

  @impl Ash.Type
  def storage_type(_), do: :map

  @impl Ash.Type
  def constraints do
    [
      version: [
        type: {:list, {:in, @versions}},
        doc: "Restrict accepted CVSS versions, e.g. [:v3, :v4]"
      ]
    ]
  end

  @impl Ash.Type
  def apply_constraints(nil, _constraints), do: {:ok, nil}

  def apply_constraints(%__MODULE__{version: version} = value, constraints) do
    allowed = Keyword.get(constraints, :version)

    if allowed && version not in allowed do
      {:error, "CVSS version #{version} is not allowed, expected one of #{inspect(allowed)}"}
    else
      {:ok, value}
    end
  end

  @impl Ash.Type
  def cast_input(nil, _), do: {:ok, nil}

  def cast_input(vector, constraints) when is_binary(vector) do
    case :cvss.parse(vector) do
      {:ok, parsed} -> cast_input(parsed, constraints)
      {:error, _} -> {:error, "invalid CVSS vector string"}
    end
  end

  def cast_input(%__MODULE__{vector: vector}, constraints) when is_binary(vector) do
    cast_input(vector, constraints)
  end

  def cast_input(parsed, constraints) when is_tuple(parsed) do
    apply_constraints(
      %__MODULE__{
        vector: IO.iodata_to_binary(:cvss.compose(parsed)),
        version: detect_version(parsed),
        score: :cvss.score(parsed),
        severity: :cvss.rating(parsed)
      },
      constraints
    )
  end

  def cast_input(_, _), do: {:error, "expected a CVSS vector string"}

  @impl Ash.Type
  def cast_stored(nil, _), do: {:ok, nil}

  def cast_stored(%{"vector" => vector, "version" => version, "score" => score, "severity" => severity}, _) do
    {:ok,
     %__MODULE__{
       vector: vector,
       version: String.to_existing_atom(version),
       score: score,
       severity: severity && String.to_existing_atom(severity)
     }}
  end

  @impl Ash.Type
  def dump_to_native(nil, _), do: {:ok, nil}

  def dump_to_native(%__MODULE__{vector: vector, version: version, score: score, severity: severity}, _) do
    {:ok,
     %{
       "vector" => vector,
       "version" => to_string(version),
       "score" => score,
       "severity" => severity && to_string(severity)
     }}
  end

  defp detect_version(parsed)
  defp detect_version(vector) when elem(vector, 0) == :cvss_v1, do: :v1
  defp detect_version(vector) when elem(vector, 0) == :cvss_v2, do: :v2
  defp detect_version(vector) when elem(vector, 0) == :cvss_v3, do: :v3
  defp detect_version(vector) when elem(vector, 0) == :cvss_v4, do: :v4

  defimpl Phoenix.HTML.Safe do
    alias Phoenix.HTML.Safe

    def to_iodata(%{vector: vector}), do: Safe.to_iodata(vector)
  end
end
