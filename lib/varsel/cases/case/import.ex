# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Import do
  @moduledoc """
  Reads a published CNA container back into case params — the inverse of
  `Varsel.Cases.Case.Calculations.Preview`, for records that were published
  before this system existed or by hand.

  ## What round-trips, and what does not

  The renderer is lossy by design: it *derives* on the way out. Anything it
  derived is skipped here rather than guessed at, so a re-render of the adopted
  case reproduces it from the facts instead of restating a stale copy.

  Imported: `title`, `datePublic`, `source.discovery`, `timeline[]`, a CVSS
  **v4** vector, `problemTypes[]` (CWE), `impacts[]` (CAPEC), `credits[]`, the
  non-derived `references[]`, and the prose fields.

  Prose takes the markdown `supportingMedia` when the record has one, else the
  HTML, else the plain-text `value`. Only the first is genuinely markdown — the
  fallbacks land in the field verbatim, HTML tags and all, for a human to tidy
  in the editor. That is the point: a rough starting text beats an empty box.

  Skipped:

    * **`affected[]`** — the case stores boundary *facts* (repo, channels,
      commit SHAs, version events) and derives the version ranges. A published
      `versions[]` block is the output of that derivation; it cannot be run
      backwards to the facts, and inventing packages from it would publish
      derived ranges as if they were authored. Affected packages are re-entered
      by hand.
    * **A non-v4 CVSS vector** — `cvss_v4` is v4-only and there is no faithful
      mechanical v3→v4 conversion. Legacy v3 records are re-scored by hand.
    * **Self-links and patch links in `references[]`** — the renderer appends
      the `cna.erlef.org`/`osv.dev` pair and one link per fixed commit on every
      publish. Storing them would duplicate them behind a stored-wins-on-URL
      conflict, and pin the commit links to versions the case no longer knows.

  What was skipped shows up as the empty sections themselves — the case page's
  section rail already marks Summary and Affected as needing attention.
  """

  alias Varsel.Cases.Case.Discovery
  alias Varsel.Cases.CaseCredit.CreditType

  @doc """
  Case params extracted from a full CVE record (`cve_json`).

  Returns only the keys with a value, so the create action's own defaults
  (`discovery: :unknown`, `timeline: []`) still apply to a sparse record.
  """
  @spec case_params(map() | nil) :: map()
  def case_params(cve_json) do
    cna = cna(cve_json)

    %{}
    |> put_present(:title, cna["title"])
    |> put_present(:description_md, description_markdown(cna))
    |> put_present(:workarounds_md, prose_markdown(cna["workarounds"]))
    |> put_present(:configurations_md, prose_markdown(cna["configurations"]))
    |> put_present(:solutions_md, prose_markdown(cna["solutions"]))
    |> put_present(:discovery, discovery(cna))
    |> put_present(:cvss_v4, cvss_v4(cna))
    |> put_present(:date_public, date_public(cna))
    |> put_present(:timeline, timeline(cna))
  end

  @doc """
  The child rows to create alongside the case, as
  `%{weaknesses: [...], impacts: [...], references: [...], credits: [...]}` —
  each a list of param maps in `position` order, without `case_id`.
  """
  @spec child_params(map() | nil) :: %{
          weaknesses: [map()],
          impacts: [map()],
          references: [map()],
          credits: [map()]
        }
  def child_params(cve_json) do
    cna = cna(cve_json)

    %{
      weaknesses: weaknesses(cna),
      impacts: impacts(cna),
      references: references(cna),
      credits: credits(cna)
    }
  end

  defp cna(cve_json) when is_map(cve_json), do: get_in(cve_json, ["containers", "cna"]) || %{}
  defp cna(_cve_json), do: %{}

  ## ------------------------------------------------------------------ prose

  # Markdown source if the record carries one, else the HTML, else the plain
  # text. Only the first is really markdown; the other two land in the field
  # as-is for a human to clean up, which beats retyping the prose from scratch.
  defp prose_markdown([%{} = entry | _rest]) do
    media = Map.get(entry, "supportingMedia", [])

    blank_to_nil(
      supporting_media(media, "text/markdown") ||
        supporting_media(media, "text/html") ||
        entry["value"]
    )
  end

  defp prose_markdown(_descriptions), do: nil

  defp supporting_media(media, type) do
    Enum.find_value(media, fn entry ->
      if entry["type"] == type and entry["base64"] != true, do: entry["value"]
    end)
  end

  # The published description carries the derived "This issue affects …" tail
  # (see Varsel.Cases.Description.AffectedSummary), which the renderer appends
  # again on every publish. Taking it along would publish it twice — and this
  # case has no affected packages yet, so the sentence describes versions it
  # can no longer justify.
  defp description_markdown(cna) do
    case prose_markdown(cna["descriptions"]) do
      nil -> nil
      markdown -> markdown |> strip_affected_summary() |> blank_to_nil()
    end
  end

  # The summary is appended as its own trailing block. In markdown and plain
  # text that is a blank-line-separated paragraph; in the HTML fallback it is a
  # <p> on its own line, so both split points are honoured.
  defp strip_affected_summary(prose) do
    {separator, joiner} =
      if String.contains?(prose, "</p>"), do: {~r/\n/, "\n"}, else: {~r/\n\s*\n/, "\n\n"}

    prose
    |> String.split(separator)
    |> Enum.reject(&affected_summary_paragraph?/1)
    |> Enum.join(joiner)
    |> String.trim()
  end

  # Matches both sentences AffectedSummary can emit, through any wrapping tag
  # the HTML fallback carries, and with the non-breaking spaces it binds
  # versions with left as-is.
  defp affected_summary_paragraph?(paragraph) do
    paragraph
    |> String.trim()
    |> String.replace(~r/^<[^>]+>/, "")
    |> String.starts_with?(["This issue affects ", "It is unknown whether "])
  end

  ## ------------------------------------------------------------ scalar fields

  defp discovery(cna) do
    with value when is_binary(value) <- get_in(cna, ["source", "discovery"]),
         {:ok, discovery} <- Discovery.cast_input(String.downcase(value), []) do
      discovery
    else
      _unknown_or_absent -> nil
    end
  end

  # v4 only: the case's cvss_v4 is v4-constrained and no faithful mechanical
  # downgrade path exists, so a v3-scored legacy record simply arrives unscored.
  defp cvss_v4(cna) do
    Enum.find_value(cna["metrics"] || [], fn metric ->
      case metric do
        %{"cvssV4_0" => %{"vectorString" => vector}} when is_binary(vector) -> vector
        _no_v4_vector -> nil
      end
    end)
  end

  defp date_public(cna), do: parse_time(cna["datePublic"])

  defp timeline(cna) do
    entries =
      for %{"time" => time, "value" => value} <- cna["timeline"] || [],
          parsed = parse_time(time),
          is_binary(value) and value != "" do
        %{time: parsed, value_md: value}
      end

    case entries do
      [] -> nil
      entries -> entries
    end
  end

  ## ------------------------------------------------------------ child rows

  # A CWE repeated across problemTypes is one classification; the case's
  # unique_case_cwe identity would reject the duplicate anyway.
  defp weaknesses(cna) do
    for_result =
      for problem_type <- cna["problemTypes"] || [],
          description <- problem_type["descriptions"] || [],
          cwe_id = numeric_id(description["cweId"], "CWE") do
        cwe_id
      end

    for_result
    |> Enum.uniq()
    |> Enum.with_index()
    |> Enum.map(fn {cwe_id, index} -> %{cwe_id: cwe_id, position: index} end)
  end

  defp impacts(cna) do
    for_result =
      for impact <- cna["impacts"] || [],
          capec_id = numeric_id(impact["capecId"], "CAPEC") do
        capec_id
      end

    for_result
    |> Enum.uniq()
    |> Enum.with_index()
    |> Enum.map(fn {capec_id, index} -> %{capec_id: capec_id, position: index} end)
  end

  defp references(cna) do
    (cna["references"] || [])
    |> Enum.reject(&derived_reference?/1)
    |> Enum.map(& &1["url"])
    |> Enum.filter(&is_binary/1)
    |> Enum.uniq()
    |> Enum.with_index()
    |> Enum.map(fn {url, index} ->
      tags = for tag <- tags_of(url, cna), is_binary(tag), do: tag

      %{url: url, tags: Enum.uniq(tags), position: index}
    end)
  end

  defp tags_of(url, cna) do
    cna["references"]
    |> Enum.filter(&(&1["url"] == url))
    |> Enum.flat_map(&(&1["tags"] || []))
  end

  # The renderer re-derives both families on every publish (self-links from the
  # CVE ID, patch links from each package's fixed commit), so storing them would
  # duplicate them — and the patch links point at commits this case has no
  # version events for yet.
  defp derived_reference?(%{"url" => url}) when is_binary(url) do
    website = Application.get_env(:varsel, :cna_website_base_url, "https://cna.erlef.org")

    String.starts_with?(url, "#{website}/cves/") or
      String.starts_with?(url, "https://osv.dev/vulnerability/EEF-") or
      String.contains?(url, "/commit/")
  end

  defp derived_reference?(_reference), do: true

  # "Name / Organization" is the EEF convention the renderer writes; split it
  # back apart so the fields are editable again. A value with no separator is
  # all name.
  defp credits(cna) do
    for {credit, index} <- Enum.with_index(cna["credits"] || []),
        value = credit["value"],
        is_binary(value) and String.trim(value) != "" do
      {name, organization} =
        case String.split(value, " / ", parts: 2) do
          [name, organization] -> {String.trim(name), blank_to_nil(String.trim(organization))}
          [name] -> {String.trim(name), nil}
        end

      %{
        name: name,
        organization: organization,
        credit_type: credit_type(credit["type"]),
        position: index
      }
    end
  end

  defp credit_type(type) when is_binary(type) do
    normalized = type |> String.trim() |> String.downcase() |> String.replace(" ", "_")

    case CreditType.cast_input(normalized, []) do
      {:ok, credit_type} -> credit_type
      _unknown -> :finder
    end
  end

  defp credit_type(_type), do: :finder

  ## ---------------------------------------------------------------- helpers

  defp numeric_id(value, prefix) when is_binary(value) do
    case Integer.parse(String.trim_leading(value, prefix <> "-")) do
      {id, ""} -> id
      _not_numeric -> nil
    end
  end

  defp numeric_id(_value, _prefix), do: nil

  defp parse_time(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, time, _offset} -> DateTime.truncate(time, :second)
      {:error, _reason} -> parse_date(value)
    end
  end

  defp parse_time(_value), do: nil

  # A date-only `datePublic` ("2026-01-15") is valid CVE 5.2; read it as midnight UTC.
  defp parse_date(value) do
    case Date.from_iso8601(value) do
      {:ok, date} -> DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
      {:error, _reason} -> nil
    end
  end

  defp put_present(params, _key, nil), do: params
  defp put_present(params, key, value), do: Map.put(params, key, value)

  defp blank_to_nil(nil), do: nil

  defp blank_to_nil(value) when is_binary(value) do
    if String.trim(value) == "", do: nil, else: value
  end
end
