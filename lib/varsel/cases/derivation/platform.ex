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

  alias Varsel.Cases.RepoUrl

  @enforce_keys [:kind]
  defstruct [:kind]

  @type kind :: :otp | :semver
  @type t :: %__MODULE__{kind: kind()}

  @doc """
  Picks the platform for an affected package: OTP's own release process for the
  erlang/otp repository, `:semver` for everything else. Deliberately keyed on the
  repository, not on `pkg:otp` channels — those exist on foreign repos too
  (Elixir's or rebar3's applications), whose releases are semver-tagged.
  """
  @spec for_package(Varsel.Cases.AffectedPackage.t()) :: t()
  def for_package(package) do
    %__MODULE__{kind: if(otp_repo?(package.repo_url), do: :otp, else: :semver)}
  end

  # Matches the erlang/otp repository exactly — not a fork, not erlang/otp_foo,
  # not erlang/rebar3. Every other repo (including erlang/rebar3 and OTP
  # applications hosted elsewhere, such as Elixir's or rebar3's) is semver.
  defp otp_repo?(nil), do: false

  defp otp_repo?(repo_url) do
    case RepoUrl.parse(repo_url) do
      %RepoUrl{host: "github.com", path: "erlang/otp"} -> true
      _not_otp -> false
    end
  end
end
