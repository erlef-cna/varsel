# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.OtpVersionsTable do
  @moduledoc """
  Queries erlang/otp's `otp_versions.table`, which maps every OTP release
  (e.g. OTP-27.3.4.1) to the exact application versions shipped in it
  (ssh-5.2.3.4, stdlib-6.2.2.1, ...). Needed to resolve `pkg:otp/<app>`
  channel boundaries from OTP release tags.

  The table is fetched from the configured URL and cached in
  `:persistent_term` for an hour.
  """

  alias Varsel.Cases.Derivation.Platform

  @cache_key {__MODULE__, :table}
  @cache_ttl_seconds 3600

  @doc "The version of `app` shipped in the given OTP release tag (e.g. \"OTP-27.3.4.1\")."
  @spec app_version(String.t(), String.t()) :: {:ok, String.t()} | :error
  def app_version(release, app) do
    release = normalize_release(release)

    with {:ok, apps} <- Map.fetch(rows(), release) do
      Map.fetch(apps, app)
    end
  end

  @doc "Every OTP release in the table, newest first."
  @spec releases() :: [String.t()]
  def releases do
    rows() |> Map.keys() |> Enum.sort_by(&Platform.parse_version(strip(&1)), :desc)
  end

  @doc """
  The version `app` had when the vulnerability was introduced: its version in
  the introducing release if it shipped there, else its version in the first
  release at-or-after that ships it (apps extracted from other apps, e.g.
  tftp split out of inets).
  """
  @spec first_shipped_version(String.t(), String.t()) :: {:ok, String.t()} | :error
  def first_shipped_version(intro_release, app) do
    intro_release = normalize_release(intro_release)

    case app_version(intro_release, app) do
      {:ok, version} ->
        {:ok, version}

      :error ->
        intro_version = Platform.parse_version(strip(intro_release))

        releases()
        |> Enum.reverse()
        |> Enum.filter(fn release -> Platform.parse_version(strip(release)) >= intro_version end)
        |> Enum.find_value(:error, &ok_app_version(&1, app))
    end
  end

  defp ok_app_version(release, app) do
    case app_version(release, app) do
      {:ok, version} -> {:ok, version}
      :error -> nil
    end
  end

  @doc "Drops the cached table (next query refetches). Used by tests."
  @spec reset() :: :ok
  def reset do
    :persistent_term.erase(@cache_key)
    :ok
  end

  defp normalize_release("OTP-" <> _ = release), do: release
  defp normalize_release(release), do: "OTP-" <> release

  defp strip("OTP-" <> version), do: version
  defp strip(release), do: release

  defp rows do
    now = System.monotonic_time(:second)

    case :persistent_term.get(@cache_key, nil) do
      {fetched_at, rows} when now - fetched_at < @cache_ttl_seconds ->
        rows

      _stale ->
        rows = fetch_and_parse()
        :persistent_term.put(@cache_key, {now, rows})
        rows
    end
  end

  defp fetch_and_parse do
    options =
      Keyword.merge(
        [
          url: "https://raw.githubusercontent.com/erlang/otp/master/otp_versions.table",
          retry: :transient
        ],
        Application.get_env(:varsel, :otp_versions_table, [])
      )

    %{status: 200, body: body} = Req.get!(options)

    body
    |> String.split("\n", trim: true)
    |> Map.new(&parse_row/1)
  end

  # A row looks like: OTP-28.3.2 : crypto-5.8.1 erts-16.2.1 # asn1-5.4.2 ... :
  # Both sides of the `#` ship in the release; `#` only separates "updated
  # here" from "carried over".
  defp parse_row(line) do
    [release | rest] = String.split(line, ~r/\s+/, trim: true)

    apps =
      rest
      |> Enum.reject(&(&1 in [":", "#"]))
      |> Map.new(&split_app/1)

    {release, apps}
  end

  # "common_test-1.27.7" -> {"common_test", "1.27.7"} (right-most "-" separates).
  defp split_app(token) do
    [version | name_parts] = token |> String.split("-") |> Enum.reverse()
    {name_parts |> Enum.reverse() |> Enum.join("-"), version}
  end
end
