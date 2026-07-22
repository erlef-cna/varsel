# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveHTML do
  @moduledoc """
  HTML rendering for CVE detail pages. The Phoenix port of the Jekyll site's
  `_layouts/cve.html`; per-field link/format logic lives in
  `VarselWeb.CveView`.
  """
  use VarselWeb, :html

  import VarselWeb.CveView

  alias VarselWeb.CveView.AffectedChecker

  embed_templates "cve_html/*"

  @doc """
  Builds the page's section list ONCE — the single source both the ToC and
  the surface-rule "every ToC section is exactly one card" ordering are
  derived from, so presence-gating never drifts between the two. Each
  section is `%{id:, toc_label:, present?:}`, in card order. "Am I
  affected?" is present whenever the record has ANY affected package at all
  (rev 3: the card always renders — no exception clause; static/no-input
  states cover shapes that can't compute, see `checker_packages/1`).
  "Affected" covers however many per-package cards render below it under
  one ToC anchor. "References" is present only when `visible_references/2`
  is non-empty — a record whose only reference is its own self-link (or a
  version-scheme tag) renders no References card at all, same as every
  other data-driven section (`cna["references"]` alone isn't enough, since
  the card body is built from the FILTERED list, not the raw one).
  """
  @spec sections(map(), String.t(), Phoenix.HTML.safe() | nil, map() | nil) :: [
          %{id: String.t(), toc_label: String.t(), present?: boolean()}
        ]
  def sections(cna, cve_id, description_prose, cvss) do
    [
      %{
        id: "am-i-affected",
        toc_label: "Am I affected?",
        present?: checker_packages(cna["affected"] || []) != []
      },
      %{id: "description", toc_label: "Description", present?: not is_nil(description_prose)},
      %{
        id: "weaknesses",
        toc_label: "Weaknesses",
        present?: cwe_descriptions(cna) != [] or capec_items(cna) != []
      },
      %{id: "affected", toc_label: "Affected", present?: (cna["affected"] || []) != []},
      %{
        id: "workarounds",
        toc_label: "Workarounds",
        present?: prose_present?(cna, "workarounds")
      },
      %{
        id: "configurations",
        toc_label: "Configurations",
        present?: prose_present?(cna, "configurations")
      },
      %{id: "solutions", toc_label: "Solutions", present?: prose_present?(cna, "solutions")},
      %{
        id: "references",
        toc_label: "References",
        present?: visible_references(cna, cve_id) != []
      },
      %{id: "credits", toc_label: "Credits", present?: (cna["credits"] || []) != []},
      %{id: "cvss-breakdown", toc_label: "CVSS breakdown", present?: not is_nil(cvss)}
    ]
  end

  defp prose_present?(cna, key), do: not is_nil(prose(cna[key], cna["references"] || []))

  @doc "Rows for the components table: zips modules / files / routines by index."
  def component_rows(entry) do
    modules = entry["modules"] || []
    files = entry["programFiles"] || []
    routines = entry["programRoutines"] || []
    max = Enum.max([length(modules), length(files), length(routines), 0])

    for i <- 0..(max - 1)//1 do
      %{
        module: Enum.at(modules, i),
        file: Enum.at(files, i),
        routine: get_in(Enum.at(routines, i) || %{}, ["name"])
      }
    end
  end

  @doc "Whether an affected entry carries any modules/files/routines to disclose."
  def has_components?(entry), do: entry["modules"] || entry["programFiles"] || entry["programRoutines"]

  @doc """
  Summary text for the components `<details>` — names only the fields
  actually present ("modules · source files" when routines are absent).
  """
  def components_summary(entry) do
    [
      entry["modules"] && "modules",
      entry["programFiles"] && "source files",
      entry["programRoutines"] && "routines"
    ]
    |> Enum.filter(& &1)
    |> Enum.join(" · ")
  end

  @doc """
  Joined CPE list for the affected card's cpe row, or nil when absent.
  Unescapes the CPE 2.3 formatted-string spec's `\\/` (a literal
  backslash-slash escaping a slash inside a field, e.g.
  `erlang\\/otp`) to a plain `/` for display — the escaping is a wire-format
  concern, not something a reader needs to see.
  """
  def cpe_line(entry) do
    case entry["cpes"] || [] do
      [] -> nil
      cpes -> Enum.map_join(cpes, ", ", &String.replace(&1, "\\/", "/"))
    end
  end

  @doc "Label + joined-value rows for the components disclosure, skipping empty fields."
  def component_field_rows(entry) do
    rows = component_rows(entry)

    [{"modules", :module}, {"source files", :file}, {"routines", :routine}]
    |> Enum.filter(fn {_label, key} -> Enum.any?(rows, &Map.get(&1, key)) end)
    |> Enum.map(fn {label, key} ->
      {label, rows |> Enum.map(&Map.get(&1, key)) |> Enum.filter(& &1) |> Enum.join(" · ")}
    end)
  end

  @doc "Formats an ISO8601 CVE metadata timestamp as `YYYY-MM-DD`, or nil when absent."
  def format_cve_date(nil), do: nil

  def format_cve_date(iso8601) do
    case DateTime.from_iso8601(iso8601) do
      {:ok, datetime, _offset} -> Date.to_iso8601(DateTime.to_date(datetime))
      {:error, _reason} -> nil
    end
  end

  @doc """
  One presentation row per DEDUPED range (rev 3, R1–R5) — `normalize_versions/1`
  collapses purl/semver/otp duplicates of the same range and strips purl
  prefixes to bare versions before this ever sees them, so a real CNA's
  multi-representation `versions[]` renders as one line per REAL branch, not
  one per representation.

  Each row is one of:

    * `%{kind: :ordered, lower:, lower_title:, fix:, fix_title:, branch_label:,
        fix_paren_label:, note:}` — R3 drops a zero/absent lower bound
      (`lower: nil`); R5: `branch_label` (leading prefix) is set only when
      the WHOLE range lies within that branch (`range_within_branch?/3`),
      otherwise the label moves into `fix_paren_label` alongside the fix note.
    * `%{kind: :git, intro_sha:, intro_sha_title:, fix_sha:, fix_sha_title:,
        note:}` — R4: no ≥/< operators (shas don't order), no repeated
        "fixed in <same sha>"; shas shorten to 7 chars with the full sha in
        a `title` attribute.
  """
  def affected_ranges(entry) do
    ranges = normalize_versions(entry["versions"] || [])
    multi_branch? = length(ranges) > 1

    Enum.map(ranges, &affected_range_row(&1, multi_branch?))
  end

  defp affected_range_row(%{"versionType" => "git"} = version, _multi_branch?) do
    # R4: a "0" (or absent) "version" is the same zero-sentinel `zero_lower?/1`
    # already strips from ordered ranges — a real ash-style git range has no
    # actual introduction sha, so "introduced by 0" must not render either.
    intro = if !zero_lower?(version["version"]), do: version["version"]
    fix = fix_boundary(version)

    %{
      kind: :git,
      intro_sha: intro && short_sha7(intro),
      intro_sha_title: intro,
      fix_sha: fix && short_sha7(fix),
      fix_sha_title: fix,
      note: git_range_note(version, fix)
    }
  end

  defp affected_range_row(version, multi_branch?) do
    type = version["versionType"]
    lower = version["version"]
    fix = fix_boundary(version)
    {label, within_branch?} = range_branch_labelling(multi_branch?, lower, fix, type)

    %{
      kind: :ordered,
      # R3: a zero/absent lower bound never prints — upper-bound-only line.
      lower: if(zero_lower?(lower), do: nil, else: lower),
      lower_title: version["version_raw"],
      fix: fix,
      fix_title: version["lessThan_raw"] || version["lessThanOrEqual_raw"],
      branch_label: within_branch? && label,
      fix_paren_label: label && not within_branch? && label,
      note: ordered_range_note(fix)
    }
  end

  defp zero_lower?(nil), do: true
  defp zero_lower?("0"), do: true
  defp zero_lower?(_other), do: false

  defp ordered_range_note(nil), do: "no fix available"
  defp ordered_range_note(fix), do: "fixed in #{fix}"

  defp git_range_note(%{"lessThan" => "*"}, nil), do: "git — no tagged release contains the fix yet"

  defp git_range_note(_version, fix) when is_binary(fix), do: "git"
  defp git_range_note(_version, nil), do: "git — no tagged release contains the fix yet"

  @doc """
  Builds the `live_render/3` session payload for `VarselWeb.AffectedCheckerLive`:
  one JSON-safe map per AFFECTED package (rev 3: every package gets an
  entry — the checker card always renders, so pills/select must count
  git-only and unorderable packages too, not just checkable ones), in the
  same relative order the Affected cards below render.

  Each package carries a `"state"`:

    * `"checkable"` — has deduped semver/otp ranges (`normalize_versions/1`,
      the SAME dedup the render path uses, so the matcher never sees a
      purl/git duplicate of a range it already has under its canonical
      type); `"versions"` holds the normalized ranges, `"otp_release?"`
      marks whether they're OTP release tags (vs. an OTP-app semver range
      with no release mapping — `"otp_package?"` says whether the PACKAGE
      is an OTP app at all, so the app-version fallback vocabulary applies
      even when the ranges are plain `semver`) so the LiveView speaks the
      right vocabulary.
    * `"all_affected"` — `defaultStatus == "affected"` with no `versions[]`
      at all: every version is affected, nothing to type (rev 3 addendum i).
    * `"git_only"` — every affected range is `git`-typed: no input, the
      commit-guidance line naming the affected/fixed shas.
    * `"unorderable"` — has affected ranges, but none are semver/otp/git
      (e.g. vendor/product-only `custom`-typed ranges): no input, the
      honest "version checking isn't available" line (rev 3 addendum ii).

  A package with NO affected status at all (nothing in `versions[]` marked
  `"affected"`, and `defaultStatus` isn't `"affected"`) is left out — there
  is nothing to check. Empty when no package qualifies; the caller skips
  mounting the checker in that case.
  """
  @spec checker_packages([map()]) :: [map()]
  def checker_packages(affected) when is_list(affected) do
    affected
    |> Enum.map(&checker_package/1)
    |> Enum.filter(& &1)
  end

  defp checker_package(entry) do
    ranges = normalize_versions(entry["versions"] || [])
    checkable = Enum.filter(ranges, &AffectedChecker.supported_type?(&1["versionType"]))
    otp_release_ranges = Enum.filter(checkable, &(&1["versionType"] == "otp"))

    base = %{
      "purl" => elem(package_link(entry), 0),
      "bare_name" => bare_package_name(entry)
    }

    if checkable == [] do
      uncheckable_package(base, entry, ranges)
    else
      checkable_package(base, entry, checkable, otp_release_ranges)
    end
  end

  defp uncheckable_package(base, entry, ranges) do
    cond do
      (entry["versions"] || []) == [] and entry["defaultStatus"] == "affected" ->
        Map.put(base, "state", "all_affected")

      ranges != [] and Enum.all?(ranges, &(&1["versionType"] == "git")) ->
        git_only_package(base, List.first(ranges))

      ranges != [] or has_affected_status?(entry) ->
        Map.put(base, "state", "unorderable")

      true ->
        nil
    end
  end

  # Rule 3: never mix vocabularies in one checker — when a record carries
  # BOTH an OTP-release-tagged range and a semver range (an OTP-app-version
  # representation from a purl entry, e.g. CVE-2098-0002's ssh record), the
  # release ranges are the ones readers actually type against, so they win
  # outright rather than matching against both comparators.
  defp checkable_package(base, entry, checkable, otp_release_ranges) do
    matched_ranges = if otp_release_ranges == [], do: checkable, else: otp_release_ranges

    Map.merge(base, %{
      "state" => "checkable",
      "versions" => matched_ranges,
      "otp_release?" => otp_release_ranges != [],
      "otp_package?" => otp_package?(entry)
    })
  end

  # Same zero-sentinel as the Affected card's git range line (R4): a "0"
  # "version" is not a real introduction sha.
  defp git_only_package(base, git_range) do
    fix = fix_boundary(git_range)
    intro = if !zero_lower?(git_range["version"]), do: git_range["version"]

    Map.merge(base, %{
      "state" => "git_only",
      "intro_sha" => intro && short_sha7(intro),
      "fix_sha" => fix && short_sha7(fix)
    })
  end

  # R5: a leading branch label is only honest when the whole range lies
  # within the fix's branch; otherwise the label qualifies the fix note.
  defp range_branch_labelling(multi_branch?, lower, fix, type) do
    label = multi_branch? && fix && branch_label(fix, type)
    {label, !!label && !!lower && range_within_branch?(lower, fix, type)}
  end

  defp has_affected_status?(entry) do
    Enum.any?(entry["versions"] || [], &(&1["status"] == "affected"))
  end

  @doc """
  DOM id for the Nth (0-indexed) per-package Affected card. Every card shares
  the ToC's single "Affected" anchor, so only the first carries `id="affected"`
  — later cards get unique ids (`affected-2`, …) so `id` never repeats on the
  page, while the ToC still jumps to the first card.
  """
  @spec affected_card_id(non_neg_integer()) :: String.t()
  def affected_card_id(0), do: "affected"
  def affected_card_id(index), do: "affected-#{index + 1}"

  @doc """
  References worth showing: drops version-scheme tags and self-links. The
  self-link filter matches on the CVE id's PATH SHAPE (`/cves/<cve_id>`,
  optionally with a `.html` suffix) rather than exact URL string equality —
  the record's own self-reference is seeded as the CANONICAL public host
  (`https://cna.erlef.org/cves/<cve_id>.html`), which never matches
  `Endpoint.url()`'s dev/test host (`http://localhost:4000/cves/<cve_id>`,
  no `.html`).
  """
  def visible_references(cna, cve_id) do
    cna
    |> Map.get("references", [])
    |> Enum.reject(fn ref ->
      "x_version-scheme" in (ref["tags"] || []) or self_reference?(ref["url"], cve_id)
    end)
  end

  defp self_reference?(url, cve_id) when is_binary(url) do
    case URI.parse(url) do
      %URI{path: path} when is_binary(path) ->
        path == "/cves/#{cve_id}" or path == "/cves/#{cve_id}.html"

      _no_path ->
        false
    end
  end

  defp self_reference?(_url, _cve_id), do: false
end
