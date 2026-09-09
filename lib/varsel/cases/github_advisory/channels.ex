# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Channels do
  @moduledoc """
  The case's distribution channels as a GitHub advisory names them, for
  `Varsel.Cases.GitHubAdvisory.Diff` and `Varsel.Cases.GitHubAdvisory.Export`
  to pair an advisory's `vulnerabilities[]` entries with the channels.

  Each channel carries the ranges the case derived for it, in GitHub's
  spelling from the derivation cache. The advisory's `ecosystem` picks the
  channel. An `erlang` entry matches the `pkg:hex` channel of that name. An
  `otp` entry matches the `pkg:otp` channel of that name. On an advisory of
  a preset repository, an application entry matches the `pkg:otp` channel
  spelled as the preset spells it
  (`Varsel.Cases.GitHubAdvisory.Import.application/2`). Any other entry
  matches a channel or a product that carries the name. Names compare
  case-insensitively.

  The case needs `Varsel.Cases.GitHubAdvisory.Export.load/0` loaded.
  """

  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.Case
  alias Varsel.Cases.GitHubAdvisory.Import

  @typedoc """
  One channel of the case: its identity, the product of its package, a
  display label and the derived ranges as
  `Varsel.Cases.Derivation.Emit.github/3` cached them.
  """
  @type t :: %{
          id: String.t(),
          purl_type: String.t() | nil,
          name: String.t() | nil,
          product: String.t() | nil,
          label: String.t(),
          github_ranges: [map()]
        }

  @doc "Every channel of the case, in package and channel order."
  @spec of_case(Case.t()) :: [t()]
  def of_case(case_record) do
    for package <- case_record.affected_packages, channel <- package.channels do
      cached =
        get_in(package.derivation_cache || %{}, ["channels", channel.id, "github_ranges"]) || []

      %{
        id: channel.id,
        purl_type: channel.purl_type,
        name: channel.name,
        product: package.product,
        label: label(channel),
        github_ranges: cached
      }
    end
  end

  @doc """
  Whether the advisory entry names `channel`. `preset` is the preset of the
  advisory's repository (`Import.preset/1`), or nil.
  """
  @spec matches?(t(), Import.vulnerability(), Preset.t() | nil) :: boolean()
  def matches?(%{purl_type: "hex", name: name}, %{ecosystem: "erlang", name: theirs}, _preset),
    do: same_name?(name, theirs)

  def matches?(_channel, %{ecosystem: "erlang"}, _preset), do: false

  def matches?(%{purl_type: "otp", name: name}, %{ecosystem: ecosystem, name: theirs}, preset)
      when is_binary(ecosystem) and not is_nil(preset), do: same_name?(name, Import.application(preset, theirs))

  def matches?(%{purl_type: "otp", name: name}, %{ecosystem: "otp", name: theirs}, _preset), do: same_name?(name, theirs)

  def matches?(_channel, %{ecosystem: "otp"}, _preset), do: false

  def matches?(%{name: name, product: product}, %{name: theirs}, _preset) do
    same_name?(name, theirs) or same_name?(product, theirs)
  end

  @doc "Whether two names are the same, case-insensitively. False when either is missing."
  @spec same_name?(term(), term()) :: boolean()
  def same_name?(name, theirs) when is_binary(name) and is_binary(theirs) do
    String.downcase(name) == String.downcase(theirs)
  end

  def same_name?(_name, _theirs), do: false

  defp label(%{kind: :service, domain: domain}), do: domain || "service"

  defp label(%{purl_type: purl_type, name: name}) when is_binary(name), do: "#{purl_type}/#{name}"

  defp label(%{purl_type: purl_type}), do: to_string(purl_type)
end
