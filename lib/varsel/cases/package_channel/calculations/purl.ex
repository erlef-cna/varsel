# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Calculations.Purl do
  @moduledoc """
  Composes a channel's stored purl parts into its Package URL string — the
  `packageURL` its `affected[]` entry publishes.

  `:service` channels have no purl (they are identified by their domain), and
  a `:package` channel missing its name cannot compose one either; both
  calculate to nil rather than to a malformed purl.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  @impl Calculation
  def load(_query, _opts, _context), do: [:kind, :purl_type, :namespace, :name, :qualifiers]

  @impl Calculation
  def calculate(channels, _opts, _context), do: Enum.map(channels, &compose/1)

  @doc "The purl string of one channel, or nil when it has no purl identity."
  @spec compose(Varsel.Cases.PackageChannel.t() | map()) :: String.t() | nil
  def compose(%{kind: :service}), do: nil
  def compose(%{name: name}) when name in [nil, ""], do: nil
  def compose(%{purl_type: purl_type}) when purl_type in [nil, ""], do: nil

  def compose(channel) do
    Purl.to_string(%Purl{
      type: channel.purl_type,
      namespace: split_namespace(channel.namespace),
      name: channel.name,
      qualifiers: channel.qualifiers || %{}
    })
  end

  defp split_namespace(nil), do: []
  defp split_namespace(namespace), do: String.split(namespace, "/", trim: true)
end
