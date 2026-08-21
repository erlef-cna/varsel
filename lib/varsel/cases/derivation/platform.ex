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

  # The one repository that uses OTP's tree versioning (OTP-/OTP_R tags). Every
  # other repo — including erlang/rebar3 and OTP applications hosted elsewhere
  # (Elixir's, rebar3's) — is semver.
  @otp_repo "github.com/erlang/otp"

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
  # not erlang/rebar3. Tolerates scheme, a `.git` suffix, and a trailing slash.
  defp otp_repo?(nil), do: false

  defp otp_repo?(repo_url) do
    repo_url
    |> String.replace(~r{^https?://}, "")
    |> String.replace(~r{\.git/?$}, "")
    |> String.trim_trailing("/")
    |> Kernel.==(@otp_repo)
  end
end
