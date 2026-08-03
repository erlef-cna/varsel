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

  alias Varsel.CVE.VersionResolution

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

  defp prose_present?(cna, key), do: not is_nil(prose(cna[key]))

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
  One presentation row per `versions[]` entry, in record order.

  A row mirrors the entry rather than interpreting it — the CVE resolution
  algorithm reads `versions[]` as a list of status assertions, so the display
  shows exactly those assertions and lets the reader see what the record
  claims:

      %{
        lower:, lower_title:,      # `version`, nil when it is the 0 sentinel
        upper:, upper_title:,      # `lessThan` / `lessThanOrEqual`, nil if absent
        upper_inclusive?:,         # `lessThanOrEqual` prints ≤, `lessThan` prints <
        open?:,                    # `lessThan: "*"` — no upper bound at all
        single?:,                  # neither bound: the entry names ONE version
        status:,                   # :affected | :unaffected | :unknown
        changes:,                  # [%{at:, at_title:, status:}] in ARRAY order
        kind:, branch_label:
      }

  `changes` keep their array order, not a sorted one: the algorithm applies
  them in the order given, so that is the order that explains the outcome.

  `kind` is `:git` for commit-sha entries, whose values shorten at render;
  `:ordered` otherwise.
  """
  def affected_ranges(entry) do
    ranges = normalize_versions(entry["versions"] || [])
    multi_branch? = length(ranges) > 1

    Enum.map(ranges, &affected_range_row(&1, multi_branch?, ranges, entry))
  end

  defp affected_range_row(version, multi_branch?, all_ranges, entry) do
    type = version["versionType"]
    lower = version["version"]
    {upper, upper_title, inclusive?, open?} = upper_bound(version)
    single? = is_nil(upper) and not open?

    %{
      kind: if(type == "git", do: :git, else: :ordered),
      # R3: the "0" sentinel is not a real bound — it means "from the start".
      lower: if(zero_lower?(lower), do: nil, else: lower),
      lower_title: version["version_raw"] || lower,
      upper: upper,
      upper_title: upper_title,
      upper_inclusive?: inclusive?,
      open?: open?,
      single?: single?,
      status: row_status(version),
      after_status: after_status(upper, all_ranges, entry["defaultStatus"]),
      changes: entry_changes(version),
      branch_label: branch_label_for(multi_branch?, lower, upper, type, entry)
    }
  end

  # What the record says about the exclusive upper bound itself — the first
  # version outside this entry. Asking the resolver keeps the colour honest: it
  # may be covered by another entry, or fall through to `defaultStatus`.
  defp after_status(nil, _all_ranges, _default_status), do: nil

  defp after_status(upper, all_ranges, default_status) do
    case VersionResolution.resolve(all_ranges, default_status, upper) do
      {:ok, status} -> status
      {:error, _reason} -> nil
    end
  end

  # `lessThan: "*"` is an open range, not a bound; `lessThanOrEqual` includes
  # its own value and prints ≤; neither present means the entry names exactly
  # one version.
  defp upper_bound(%{"lessThan" => "*"}), do: {nil, nil, false, true}
  defp upper_bound(%{"lessThanOrEqual" => "*"}), do: {nil, nil, true, true}

  defp upper_bound(%{"lessThan" => lt} = version) when is_binary(lt),
    do: {lt, version["lessThan_raw"] || lt, false, false}

  defp upper_bound(%{"lessThanOrEqual" => lte} = version) when is_binary(lte),
    do: {lte, version["lessThanOrEqual_raw"] || lte, true, false}

  defp upper_bound(_single_version), do: {nil, nil, false, false}

  # Every transition, in the order the record lists them — that is the order the
  # algorithm applies, so re-sorting would misexplain the result.
  defp entry_changes(version) do
    for change <- List.wrap(version["changes"]), is_binary(change["at"]) do
      %{
        at: change["at"],
        at_title: change["at_raw"] || change["at"],
        status: row_status(change)
      }
    end
  end

  # A row states its own status. Anything not explicitly `unaffected` or
  # `unknown` is affected — an absent status is only legal on `changes`, and the
  # schema requires one on every entry.
  defp row_status(%{"status" => "unaffected"}), do: :unaffected
  defp row_status(%{"status" => "unknown"}), do: :unknown
  defp row_status(_affected), do: :affected

  defp zero_lower?(nil), do: true
  defp zero_lower?("0"), do: true
  defp zero_lower?(_other), do: false

  @doc """
  Builds the `live_render/3` session payload for `VarselWeb.AffectedCheckerLive`:
  one JSON-safe map per affected package, in the same relative order the
  Affected cards below render.

  Each package carries:

    * `"versions"` — its normalized ranges (`normalize_versions/1`, the SAME
      dedup the render path uses, so the checker never sees a purl duplicate of
      a range it already has under its canonical type).
    * `"default_status"` — the entry's `defaultStatus`, which the resolution
      algorithm needs: it is the answer for every version no range covers.
    * `"askable?"` — whether `Varsel.CVE.VersionResolution` can order these
      ranges at all. False for a product versioned by commit sha, `custom`
      string, or anything else with no comparison; the LiveView then shows the
      ranges instead of an input, since it could never answer a typed version.
    * `"otp_release?"` / `"otp_package?"` — vocabulary hints, so the input
      placeholder and verdict read "Erlang 27.3.4" rather than a bare version.

  A package with nothing to say — no ranges and no `defaultStatus` — is left
  out. Empty when no package qualifies; the caller skips mounting the checker.
  """
  @spec checker_packages([map()]) :: [map()]
  def checker_packages(affected) when is_list(affected) do
    affected
    |> Enum.map(&checker_package/1)
    |> Enum.filter(& &1)
  end

  defp checker_package(entry) do
    ranges = normalize_versions(entry["versions"] || [])

    if ranges == [] and is_nil(entry["defaultStatus"]) do
      nil
    else
      # Rule 3: never mix vocabularies in one checker — when a record carries
      # BOTH an OTP-release-tagged range and a semver range (an OTP-app-version
      # representation from a purl entry, e.g. CVE-2098-0002's ssh record), the
      # release ranges are the ones readers actually type against.
      otp_release_ranges = Enum.filter(ranges, &(&1["versionType"] == "otp"))
      asked = if otp_release_ranges == [], do: ranges, else: otp_release_ranges

      %{
        "purl" => entry["packageURL"],
        "package_fallback" => "#{entry["vendor"]} / #{entry["product"]}",
        "bare_name" => bare_package_name(entry),
        "versions" => asked,
        "default_status" => entry["defaultStatus"],
        "askable?" => VersionResolution.resolvable?(asked),
        "otp_release?" => otp_release_ranges != [],
        "otp_package?" => otp_package?(entry)
      }
    end
  end

  # R5: a leading branch label is only honest when the whole range lies within
  # the fix's branch. A range spanning lines gets none — the label would claim a
  # confinement it doesn't have, and it says nothing the fix version doesn't
  # already (it IS the fix version, truncated).
  #
  # SEVERAL fixes mean the range crosses a line per fix by construction (an OTP
  # range fixed in 27.3.4.15, 28.5.0.4 and 29.0.4 covers three majors), so there
  # is no one branch to name.
  defp branch_label_for(multi_branch?, lower, upper, type, entry) when is_binary(upper) do
    label = multi_branch? && branch_labellable?(type, entry) && branch_label(upper, type)

    if label && lower && range_within_branch?(lower, upper, type), do: label
  end

  defp branch_label_for(_multi_branch?, _lower, _upper, _type, _entry), do: nil

  # OTP's `maint-N` branches track RELEASE versions, so only a product versioned
  # by release may be labelled with one. An application's own version (ssh 5.3,
  # from a `pkg:otp/ssh` entry) has no such branch — `maint-5` would name a git
  # ref that does not exist. Semver products label by series and are unaffected
  # by this.
  defp branch_labellable?("otp", entry), do: otp_release_entry?(entry["packageURL"])
  defp branch_labellable?(_type, _entry), do: true

  # The release channels: the repository itself, and the distribution as a whole.
  defp otp_release_entry?(nil), do: false
  defp otp_release_entry?("pkg:sid/erlang.org/otp" <> _rest), do: true
  defp otp_release_entry?("pkg:github/" <> _rest), do: true
  defp otp_release_entry?(_application), do: false

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
