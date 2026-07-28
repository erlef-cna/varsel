# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Types.URI do
  @moduledoc """
  Custom Ash type for URLs, stored in the form `URI.new/1` parses them into.

  Casting parses and re-serializes, lowercasing the scheme and host, so
  `HTTPS://Example.COM/x` is stored as `https://example.com/x`.

  Values are stored as `:string`, so an existing `:string` attribute can adopt
  this type without a migration.

  ## Constraints

    * `:schemes` — the schemes accepted, e.g. `schemes: ["https"]`. Compared
      against the parsed (lowercased) scheme. Omit to accept any.
    * `:absolute` — when `true`, a URL without both a scheme and a host is
      rejected, so `/x` and `//example.com/x` do not pass. Defaults to `false`.
    * `:public_host` — when `true`, a host that resolves to a private or
      otherwise non-routable address is rejected (see `Varsel.Net.PrivateAddress`).
      Resolves the host, so it does DNS on cast. Defaults to `false`.

  A relative or scheme-less URL parses fine, so constrain explicitly when the
  attribute needs an absolute one:

      attribute :repo_url, Varsel.Types.URI do
        constraints schemes: ["https"], absolute: true, public_host: true
      end

  `:public_host` resolves the host when the value is cast, so it says nothing
  about what that name answers with later.
  """

  @behaviour AshGraphql.Type

  use Ash.Type

  alias Varsel.Net.PrivateAddress

  # A string on the wire both ways — the normalization is server-side, so a
  # client sends and receives the plain URL.
  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :string

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :string

  @impl Ash.Type
  def storage_type(_constraints), do: :string

  @impl Ash.Type
  def constraints do
    [
      schemes: [
        type: {:list, :string},
        doc: ~s{Accepted URL schemes, e.g. ["https"]. Omit to accept any.}
      ],
      absolute: [
        type: :boolean,
        default: false,
        doc: "Require a scheme and a host, rejecting relative and scheme-relative URLs."
      ],
      public_host: [
        type: :boolean,
        default: false,
        doc: "Reject a host that resolves to a private/non-routable address."
      ]
    ]
  end

  @impl Ash.Type
  def cast_input(nil, _constraints), do: {:ok, nil}

  def cast_input(%URI{} = uri, _constraints), do: {:ok, uri |> downcase_host() |> URI.to_string()}

  def cast_input(value, _constraints) when is_binary(value) do
    case URI.new(value) do
      {:ok, uri} -> {:ok, uri |> downcase_host() |> URI.to_string()}
      {:error, _invalid} -> {:error, message: "is not a valid URL"}
    end
  end

  def cast_input(_value, _constraints), do: {:error, message: "is not a valid URL"}

  # Stored values were normalized on the way in, so they are returned as-is
  # rather than re-parsed — a row written before an attribute adopted this
  # type keeps whatever it holds until something writes it again.
  @impl Ash.Type
  def cast_stored(nil, _constraints), do: {:ok, nil}
  def cast_stored(value, _constraints) when is_binary(value), do: {:ok, value}
  def cast_stored(_value, _constraints), do: :error

  @impl Ash.Type
  def dump_to_native(nil, _constraints), do: {:ok, nil}
  def dump_to_native(value, _constraints) when is_binary(value), do: {:ok, value}
  def dump_to_native(_value, _constraints), do: :error

  @impl Ash.Type
  def apply_constraints(nil, _constraints), do: {:ok, nil}

  def apply_constraints(value, constraints) do
    # Re-parsed rather than threaded from cast_input/2: apply_constraints/2 also
    # runs on its own (e.g. an already-cast value), so it cannot assume it does.
    case URI.new(value) do
      {:ok, uri} -> check(downcase_host(uri), constraints)
      {:error, _invalid} -> {:error, message: "is not a valid URL"}
    end
  end

  defp check(uri, constraints) do
    with :ok <- check_scheme(uri, Keyword.get(constraints, :schemes)),
         :ok <- check_absolute(uri, Keyword.get(constraints, :absolute, false)),
         :ok <- check_public(uri, Keyword.get(constraints, :public_host, false)) do
      {:ok, URI.to_string(uri)}
    end
  end

  # A host is case-insensitive, so it is stored in one case. `URI.new/1`
  # lowercases the scheme but leaves the host as written.
  defp downcase_host(%URI{host: host} = uri) when is_binary(host), do: %{uri | host: String.downcase(host, :ascii)}

  defp downcase_host(uri), do: uri

  defp check_scheme(_uri, nil), do: :ok

  defp check_scheme(%URI{scheme: scheme}, schemes) do
    if scheme in schemes do
      :ok
    else
      {:error, message: "must be a #{Enum.join(schemes, " or ")} URL"}
    end
  end

  defp check_absolute(_uri, false), do: :ok

  defp check_absolute(%URI{scheme: scheme, host: host}, true) when is_binary(scheme) and is_binary(host) and host != "",
    do: :ok

  # `//example.com/x` has a host but no scheme, and `/x` has neither.
  defp check_absolute(_uri, true), do: {:error, message: "must be an absolute URL"}

  defp check_public(_uri, false), do: :ok

  defp check_public(%URI{host: host}, true) when is_binary(host) and host != "" do
    if PrivateAddress.private_host?(host) do
      {:error, message: "must resolve to a public host (private/internal addresses are not allowed)"}
    else
      :ok
    end
  end

  # No host to resolve — `absolute` is the constraint for that.
  defp check_public(_uri, true), do: :ok
end
