# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Preset do
  @moduledoc """
  The well-known-product catalog behind the specialized "add affected
  package" actions (`add_otp` / `add_elixir` / `add_gleam` on
  `Varsel.Cases.AffectedPackage`) and preset `:insert` proposals.

  A preset pins the package constants exactly as the published EEF CNA
  records spell them (vendor/product/repo/CPE) and expands the user-supplied
  facts into child rows:

  * `:otp` — one `pkg:otp/<application>` channel per affected OTP
    application, subpath `lib/<application>` (`erts` for erts); boundaries
    resolve to per-application versions through
    `Varsel.Cases.Derivation.OtpVersionsTable`.
  * `:elixir` — one `pkg:otp/<application>` channel per affected Elixir
    application (elixir, eex, ex_unit, iex, logger, mix), subpath
    `lib/<application>`; Elixir's applications version with Elixir itself,
    so ranges derive as semver from the elixir-lang/elixir tags.
  * `:gleam` — the `pkg:sid/gleam.run/gleam` tool channel plus the ghcr.io
    OCI image channel with its tag flavors.

  When vulnerable functionality moved from one OTP application to another
  over time (ftp/tftp split out of inets), the derived range of the *former*
  home is wrong by construction — the fix releases still ship that
  application. Bound the old application's channel with channel-scoped
  explicit version events instead (see CVE-2026-48858's inets entry).
  """

  @type t :: :otp | :elixir | :gleam

  @values [:otp, :elixir, :gleam]

  # Every published Gleam CVE repeats the derived range once per image flavor.
  @gleam_tag_suffixes ~w(elixir erlang node node-slim elixir-slim erlang-slim
                         erlang-alpine elixir-alpine node-alpine scratch)

  @doc "All known presets."
  @spec values() :: [t()]
  def values, do: @values

  @doc "Casts external preset input (proposal payloads) to a known preset."
  @spec cast(term()) :: {:ok, t()} | :error
  def cast(preset) when preset in @values, do: {:ok, preset}

  def cast(preset) when is_binary(preset) do
    Enum.find_value(@values, :error, &if(to_string(&1) == preset, do: {:ok, &1}))
  end

  def cast(_preset), do: :error

  @doc """
  The `Varsel.Cases.AffectedPackage` constants a preset stamps, spelled as
  the published records spell them. The CPE is explicit where the default
  vendor/product derivation would differ from the CPE dictionary name.
  """
  @spec attributes(t()) :: %{atom() => String.t()}
  def attributes(:otp) do
    %{
      vendor: "Erlang",
      product: "OTP",
      repo_url: "https://github.com/erlang/otp",
      cpe: ~S(cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*)
    }
  end

  def attributes(:elixir) do
    %{
      vendor: "elixir-lang",
      product: "elixir",
      repo_url: "https://github.com/elixir-lang/elixir"
    }
  end

  def attributes(:gleam) do
    %{
      vendor: "Gleam",
      product: "Gleam",
      repo_url: "https://github.com/gleam-lang/gleam",
      cpe: "cpe:2.3:a:gleam-lang:gleam:*:*:*:*:*:*:*:*"
    }
  end

  @doc "Whether the preset takes a list of affected applications."
  @spec applications?(t()) :: boolean()
  def applications?(:gleam), do: false
  def applications?(_preset), do: true

  @doc "The `Varsel.Cases.PackageChannel` `:add` params a preset expands to."
  @spec channels(t(), [String.t()] | nil) :: [map()]
  def channels(:gleam, _applications) do
    [
      %{purl_type: :sid, namespace: "gleam.run", name: "gleam", position: 0},
      %{
        purl_type: :oci,
        name: "gleam",
        qualifiers: %{"repository_url" => "ghcr.io/gleam-lang"},
        tag_suffixes: @gleam_tag_suffixes,
        position: 1
      }
    ]
  end

  def channels(_otp_or_elixir, applications) do
    applications
    |> Enum.with_index()
    |> Enum.map(fn {application, position} ->
      %{
        purl_type: :otp,
        name: application,
        subpath: application_subpath(application),
        position: position
      }
    end)
  end

  # Both repositories keep their applications under lib/<application>; erts
  # lives at the erlang/otp repository root.
  defp application_subpath("erts"), do: "erts"
  defp application_subpath(application), do: "lib/#{application}"

  @doc """
  The keys a preset `:insert` proposal payload may carry (besides `preset`
  itself): the specialized action's arguments plus the content fields it
  accepts.
  """
  @spec payload_fields(t()) :: [atom()]
  def payload_fields(preset) do
    arguments(preset) ++ [:program_files]
  end

  @doc "The specialized action's argument names for a preset."
  @spec arguments(t()) :: [atom()]
  def arguments(:gleam), do: [:introduced_commit, :fixed_commits]
  def arguments(_preset), do: [:applications, :introduced_commit, :fixed_commits]

  @doc "Regex a boundary commit argument must match (mirrors `Varsel.Cases.VersionEvent`)."
  @spec commit_sha_regex() :: Regex.t()
  def commit_sha_regex, do: ~r/^[0-9a-f]{40}$/
end
