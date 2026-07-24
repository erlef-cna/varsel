# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.Platform do
  @moduledoc """
  The versioning scheme of a package's release process — the one knob the
  derivation pipeline needs to pick a `Varsel.Cases.Reachability.VersionComparator`
  kind:

  * `:otp` — Erlang/OTP (`OTP-` / legacy `OTP_R` tags, a version tree).
  * `:semver` — everything else.
  """

  @enforce_keys [:kind]
  defstruct [:kind]

  @type kind :: :otp | :semver
  @type t :: %__MODULE__{kind: kind()}

  @doc """
  Picks the platform for an affected package: erlang/otp's own release process
  for packages living in the erlang/otp repository, `:semver` for everything
  else. Deliberately keyed on the repository, not on `pkg:otp` channels — those
  exist on foreign repos too (Elixir's or rebar3's applications), whose releases
  are semver-tagged.
  """
  @spec for_package(Varsel.Cases.AffectedPackage.t()) :: t()
  def for_package(package) do
    kind = if (package.repo_url || "") =~ ~r{github\.com/erlang/otp}, do: :otp, else: :semver
    %__MODULE__{kind: kind}
  end

  @doc """
  Sortable representation of a numeric OTP version string: numeric parts, with
  released versions ranking above pre-releases of the same number. Used by
  `Varsel.Cases.Derivation.OtpVersionsTable` to order OTP releases.
  """
  @spec parse_version(String.t()) :: {[integer()], 0 | 1, String.t()}
  def parse_version(version) do
    {numeric, suffix} =
      case String.split(version, "-", parts: 2) do
        [n] -> {n, ""}
        [n, s] -> {n, s}
      end

    nums =
      numeric
      |> String.split(".")
      |> Enum.map(fn part ->
        case Integer.parse(part) do
          {i, ""} -> i
          _ -> 0
        end
      end)

    suffix_rank = if suffix == "", do: 1, else: 0
    {nums, suffix_rank, suffix}
  end
end
