# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveView do
  @moduledoc """
  Shared rendering helpers for CVE records — the Phoenix port of the Jekyll
  site's `package-link.html`, `version-link.html`, `link_commit_shas.rb`, and
  the per-ecosystem link derivation baked into `cve.html`.

  Functions come in two flavours:

    * plain helpers returning data (`best_cvss/1`,
      `package_link/1` → `{label, url}`) used from templates and tests, and
    * `Phoenix.Component` function components (`package_ref/1`, `version_ref/1`)
      that render the same markup the site produced.
  """
  use Phoenix.Component

  alias Phoenix.HTML.Engine
  alias VarselWeb.CveView.AffectedChecker

  @sha_regex ~r/\b[0-9a-f]{40}\b/

  ## ---------------------------------------------------------------- CVSS

  @doc """
  Picks the most relevant CVSS metric from a CNA container's `metrics`,
  preferring v4.0 > v3.1 > v3.0. Returns the inner cvss map (with an added
  `"version"`) or nil.
  """
  @spec best_cvss(map()) :: map() | nil
  def best_cvss(cna) when is_map(cna) do
    metrics = cna["metrics"] || []

    Enum.find_value(["cvssV4_0", "cvssV3_1", "cvssV3_0"], fn key ->
      Enum.find_value(metrics, &cvss_of(&1, key))
    end)
  end

  defp cvss_of(%{} = metric, key) do
    case metric do
      %{^key => %{} = cvss} -> Map.put_new(cvss, "version", version_of(key))
      _ -> nil
    end
  end

  defp version_of("cvssV4_0"), do: "4.0"
  defp version_of("cvssV3_1"), do: "3.1"
  defp version_of("cvssV3_0"), do: "3.0"

  @doc "Link to the appropriate CVSS calculator for a vector string, or nil."
  @spec cvss_calculator_url(map()) :: String.t() | nil
  def cvss_calculator_url(%{"version" => "4.0", "vectorString" => vector}),
    do: "https://nvd.nist.gov/site-scripts/cvss-v4-calculator-main/index.html##{vector}"

  def cvss_calculator_url(%{"version" => "3.1", "vectorString" => vector}),
    do: "https://chandanbn.github.io/cvss/##{vector}"

  def cvss_calculator_url(_other), do: nil

  @doc """
  Renders a CVSS vector string as its own wrapped mono block line: wraps
  ONLY at "/" boundaries via `<wbr>`, never truncates, never scrolls, never
  `break-all`s (which would break mid-token, e.g. "A|V:N"). Built as a raw
  HTML string (not a HEEx `for` comprehension) so no incidental whitespace
  sneaks between segments — `<wbr>` itself contributes no characters to the
  copied text, so the rendered string remains one selectable/copyable whole.
  """
  attr :vector, :string, required: true
  attr :class, :any, default: nil

  def cvss_vector(assigns) do
    assigns = assign(assigns, :wrapped, wrap_vector(assigns.vector))

    ~H"""
    <code class={["block font-mono text-[0.7rem] leading-[1.6] text-base-content/60", @class]}>{@wrapped}</code>
    """
  end

  defp wrap_vector(vector) do
    iodata =
      vector
      |> String.split("/")
      |> Enum.map_intersperse("/<wbr>", &Engine.html_escape/1)

    {:safe, iodata}
  end

  ## ---------------------------------------------------------------- CWE / CAPEC

  @doc "The primary English CWE problemType description, or nil."
  @spec cwe_description(map()) :: map() | nil
  def cwe_description(cna) when is_map(cna) do
    cna |> cwe_descriptions() |> List.first()
  end

  @doc "Every English CWE problemType description (a record usually carries exactly one)."
  @spec cwe_descriptions(map()) :: [map()]
  def cwe_descriptions(cna) when is_map(cna) do
    cna
    |> Map.get("problemTypes", [])
    |> Enum.flat_map(&Map.get(&1, "descriptions", []))
    |> Enum.filter(&(&1["lang"] == "en" and &1["type"] == "CWE" and &1["cweId"]))
  end

  @doc "CAPEC impact entries that carry a capecId."
  @spec capec_items(map()) :: [map()]
  def capec_items(cna) when is_map(cna), do: cna |> Map.get("impacts", []) |> Enum.filter(& &1["capecId"])

  @doc "MITRE definition URL for a `CWE-NNN` id."
  def cwe_url("CWE-" <> number), do: "https://cwe.mitre.org/data/definitions/#{number}.html"

  @doc "MITRE definition URL for a `CAPEC-NNN` id."
  def capec_url("CAPEC-" <> number), do: "https://capec.mitre.org/data/definitions/#{number}.html"

  @doc "Parses the numeric id out of a `CWE-NNN` string, for local catalog map lookups."
  @spec cwe_id_number(String.t()) :: integer()
  def cwe_id_number("CWE-" <> number), do: String.to_integer(number)

  @doc "Parses the numeric id out of a `CAPEC-NNN` string, for local catalog map lookups."
  @spec capec_id_number(String.t()) :: integer()
  def capec_id_number("CAPEC-" <> number), do: String.to_integer(number)

  @doc """
  First English description of a CAPEC impact entry — the sub-line under
  the id·name chip, suppressed when it says no more than the chip already
  does.

  With a catalog name: render generators commonly emit "CAPEC-63 Cross-Site
  Scripting (XSS)" as the impact description, a pure restatement of the
  chip above it — suppressed. Only prose saying MORE than id + catalog name
  earns the sub-line.

  With NO catalog name (id not in the local catalog, `catalog_name == nil`):
  there is nothing to restate, so the sub-line renders whenever the
  description is non-empty after stripping the bare id — it is the only
  information anyone has about the pattern. A nil `catalog_name` must never
  itself be folded into a restatement string (a naive `"\#{id} \#{nil}"`
  interpolation would produce the literal text "CAPEC-99999 nil" and could
  spuriously match).
  """
  def capec_text(impact, catalog_name \\ nil) do
    text =
      impact
      |> Map.get("descriptions", [])
      |> Enum.find_value(fn d -> if d["lang"] == "en", do: d["value"] end)

    id = impact["capecId"] || ""

    restatements =
      [
        id,
        catalog_name,
        catalog_name && "#{id} #{catalog_name}",
        catalog_name && "#{id}: #{catalog_name}"
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&normalize_impact/1)

    if text && normalize_impact(text) not in restatements, do: text
  end

  defp normalize_impact(text) do
    text |> String.downcase() |> String.replace(~r/[^a-z0-9]+/, "")
  end

  ## ---------------------------------------------------------------- Package links

  @doc """
  Derives `{label, url}` for an affected entry's package, mapping purl types
  to their registry web pages. `url` is nil when no link applies (the caller
  then renders just the label). Falls back to `vendor / product`.
  """
  @spec package_link(map()) :: {String.t(), String.t() | nil}
  def package_link(entry) when is_map(entry) do
    case parse_purl(entry["packageURL"]) do
      {:ok, %Purl{type: "hex"} = purl} ->
        name = purl_name(purl)
        {"pkg:hex/#{name}", "https://hex.pm/packages/#{name}"}

      {:ok, %Purl{type: "npm"} = purl} ->
        name = purl_name(purl)
        {"pkg:npm/#{name}", "https://www.npmjs.com/package/#{name}"}

      {:ok, %Purl{type: "github"} = purl} ->
        path = purl_name(purl)
        {"pkg:github/#{path}", "https://github.com/#{path}"}

      {:ok, %Purl{type: "oci"} = purl} ->
        oci_link(entry, purl)

      {:ok, purl} ->
        {Purl.to_string(%{purl | version: nil, qualifiers: %{}, subpath: []}), nil}

      :error ->
        {"#{entry["vendor"]} / #{entry["product"]}", nil}
    end
  end

  defp oci_link(entry, purl) do
    label = "pkg:oci/#{purl_name(purl)}"

    if is_binary(entry["packageURL"]) and String.contains?(entry["packageURL"], "ghcr.io") and
         entry["packageName"] do
      {label, "https://github.com/#{entry["packageName"]}/pkgs/container/#{purl_name(purl)}"}
    else
      {label, nil}
    end
  end

  @doc """
  Derives `{label, url}` for the Affected card header's REGISTRY link, or nil
  when no clean registry link applies. Deliberately narrower than
  `package_link/1`: a github-type purl's url already points at the repo
  page, so it's covered by the `repo` header link instead of a redundant
  "GitHub ↗" registry entry (`entry["repo"]` renders separately).
  """
  @spec registry_link(map()) :: {String.t(), String.t()} | nil
  def registry_link(entry) when is_map(entry) do
    case parse_purl(entry["packageURL"]) do
      {:ok, %Purl{type: "hex"} = purl} ->
        {"Hex.pm", "https://hex.pm/packages/#{purl_name(purl)}"}

      {:ok, %Purl{type: "npm"} = purl} ->
        {"npm", "https://www.npmjs.com/package/#{purl_name(purl)}"}

      {:ok, %Purl{type: "oci"} = purl} ->
        oci_registry_link(entry, purl)

      _other ->
        nil
    end
  end

  defp oci_registry_link(entry, purl) do
    case oci_link(entry, purl) do
      {_label, url} when is_binary(url) -> {"Container registry", url}
      _no_link -> nil
    end
  end

  @doc """
  Component rendering an affected entry's package reference as `<code>` text,
  optionally linked. Mirrors `_includes/package-link.html`.
  """
  attr :entry, :map, required: true
  attr :link, :boolean, default: false

  def package_ref(assigns) do
    {label, url} = package_link(assigns.entry)
    linked? = assigns.link and not is_nil(url)
    assigns = assign(assigns, label: label, url: url, linked?: linked?)

    ~H"""
    <a :if={@linked?} href={@url} target="_blank" rel="noopener">
      <code>{@label}</code>
    </a>
    <code :if={not @linked?}>{@label}</code>
    """
  end

  @doc """
  Renders an affected entry's package as the `.pkg` mono chip (base surface,
  soft border, ~5px radius) — used in the header band's chip row and the
  Affected card heading, distinct from `package_ref/1`'s plain `<code>` text.
  """
  attr :entry, :map, required: true
  attr :class, :any, default: nil

  def package_chip(assigns) do
    {label, _url} = package_link(assigns.entry)
    assigns = assign(assigns, label: label)

    ~H"""
    <code class={[
      "inline-block whitespace-nowrap rounded-[5px] border border-base-300/70 bg-base-100",
      "px-[0.4rem] py-[0.07rem] text-[0.71rem] text-base-content/70",
      @class
    ]}>
      {@label}
    </code>
    """
  end

  @doc """
  The bare package name for an affected entry — `bandit`, `erlang/otp`, no
  `pkg:type/` prefix — for spots that need a short name rather than the full
  purl chip label (the checker's placeholder and verdict copy: `bandit
  version, e.g. …`, `✗ cowlib 2.11.0 is affected`). Falls back to
  `vendor/product` when there's no parseable purl.
  """
  @spec bare_package_name(map()) :: String.t()
  def bare_package_name(entry) when is_map(entry) do
    case parse_purl(entry["packageURL"]) do
      {:ok, purl} -> purl_name(purl)
      :error -> "#{entry["vendor"]}/#{entry["product"]}"
    end
  end

  @doc """
  Whether an affected entry's package is an OTP application (`pkg:otp/*`
  purl type) — drives the checker's OTP-release-vs-application-version
  vocabulary choice (rev 3): even when a record's ranges are `semver`-typed
  (an OTP app version with no release mapping), an `pkg:otp/*` package
  still speaks the "OTP application" fallback vocabulary rather than a bare
  hex-style verdict.
  """
  @spec otp_package?(map()) :: boolean()
  def otp_package?(entry) when is_map(entry) do
    match?({:ok, %Purl{type: "otp"}}, parse_purl(entry["packageURL"]))
  end

  ## ---------------------------------------------------------------- id·name chips

  @doc """
  Renders the `.idn` id·name chip: a mono catalog id, a `·` separator, then
  the catalog name in the normal text face. The id NEVER truncates. The name
  truncates (`overflow-hidden text-ellipsis whitespace-nowrap` under the
  caller-supplied `name_class` max-width) only when `truncate?` is true — the
  header band's cramped chip row is the one place that applies; every
  in-card usage (Weaknesses card's CWE/CAPEC rows) sets `truncate?={false}`
  so the full catalog name wraps to multiple lines instead, with the id
  staying put via `items-start` (the id and the link cluster otherwise
  vertically center against a name that may now be several lines tall). When
  `name` is nil (a catalog lookup miss), renders the bare id with no
  dangling separator.
  """
  attr :id, :string, required: true
  attr :name, :string, default: nil
  attr :class, :any, default: nil
  attr :name_class, :any, default: nil
  attr :truncate?, :boolean, default: true

  def id_name_chip(assigns) do
    ~H"""
    <span class={[
      "inline-flex min-w-0 max-w-full gap-[0.4ch] rounded-[5px] border border-base-300/70",
      if(@truncate?, do: "items-center", else: "items-start"),
      "bg-base-100 px-[0.45rem] py-[0.07rem] text-[0.71rem] text-base-content/70",
      @class
    ]}>
      <code class="shrink-0">{@id}</code>
      <span :if={@name}>·</span>
      <span
        :if={@name}
        class={[
          if(@truncate?, do: "overflow-hidden text-ellipsis whitespace-nowrap", else: "break-words"),
          @name_class
        ]}
      >
        {@name}
      </span>
    </span>
    """
  end

  ## ---------------------------------------------------------------- Version links

  @doc """
  Derives `{label, url}` for a single version string of a given type within an
  affected entry. `url` is nil when the version should render without a link.
  Mirrors `_includes/version-link.html`.
  """
  @spec version_link(String.t() | nil, String.t() | nil, map()) :: {String.t(), String.t() | nil}
  def version_link("*", _type, _entry), do: {"no fix available", nil}
  def version_link("0", _type, _entry), do: {"initial", nil}

  def version_link(version, "git", %{"repo" => repo}) when is_binary(repo) do
    if String.contains?(repo, "github.com") do
      {short_sha(version), "#{String.replace(repo, ".git", "")}/tree/#{version}"}
    else
      {version, nil}
    end
  end

  def version_link(version, "otp", %{"packageName" => "erlang/otp"}),
    do: {version, "https://www.erlang.org/patches/otp-#{version}"}

  def version_link(version, "semver", entry) do
    case parse_purl(entry["packageURL"]) do
      {:ok, %Purl{type: "hex"} = purl} ->
        {version, "https://hex.pm/packages/#{purl_name(purl)}/#{version}"}

      _other ->
        {version, nil}
    end
  end

  def version_link(version, _type, entry) do
    with purl_string when is_binary(purl_string) <- entry["packageURL"],
         true <-
           String.contains?(purl_string, "pkg:oci/") and String.contains?(purl_string, "ghcr.io"),
         {:ok, purl} <- parse_purl(purl_string) do
      {version, "https://github.com/#{entry["packageName"]}/pkgs/container/#{purl_name(purl)}"}
    else
      _other -> {version, nil}
    end
  end

  @doc "Component rendering a version reference. Mirrors `version-link.html`."
  attr :version, :string, required: true
  attr :type, :string, default: nil
  attr :entry, :map, required: true

  def version_ref(assigns) do
    {label, url} = version_link(assigns.version, assigns.type, assigns.entry)
    no_fix? = assigns.version == "*"

    assigns =
      assign(assigns,
        label: label,
        url: url,
        no_fix?: no_fix?,
        linked?: not no_fix? and not is_nil(url)
      )

    ~H"""
    <em :if={@no_fix?}>no fix available</em>
    <a :if={@linked?} href={@url} target="_blank" rel="noopener"><code>{@label}</code></a>
    <code :if={not @no_fix? and not @linked?}>{@label}</code>
    """
  end

  ## ---------------------------------------------------------------- Commit SHAs

  @doc """
  Rewrites bare 40-hex commit SHAs in advisory HTML into links to their GitHub
  commit URL, using the record's references to discover the repo. Port of
  `_plugins/link_commit_shas.rb`. Returns safe HTML.

  The commit base URL is taken from the first reference whose URL matches a
  GitHub `.../commit/<sha>` shape; SHAs are shown truncated to 10 chars.
  """
  @spec link_commit_shas(String.t(), [map()]) :: Phoenix.HTML.safe()
  def link_commit_shas(html, references) when is_binary(html) do
    case commit_base_url(references) do
      nil ->
        Phoenix.HTML.raw(html)

      base ->
        Phoenix.HTML.raw(
          Regex.replace(@sha_regex, html, fn sha ->
            ~s(<a href="#{base}#{sha}" class="link link-primary"><code>#{String.slice(sha, 0, 10)}</code></a>)
          end)
        )
    end
  end

  defp commit_base_url(references) when is_list(references) do
    Enum.find_value(references, fn ref ->
      case Regex.run(
             ~r/^(https:\/\/github\.com\/[^\/]+\/[^\/]+\/commit\/)[0-9a-f]{40}/,
             ref["url"] || ""
           ) do
        [_full, base] -> base
        _no_match -> nil
      end
    end)
  end

  defp commit_base_url(_references), do: nil

  ## ---------------------------------------------------------------- Markdown

  @doc """
  Renders advisory prose: prefers an English `text/html` supportingMedia value,
  otherwise renders the entry's markdown `value`. The result is run through
  `link_commit_shas/2`. `entries` is a `descriptions`/`workarounds`/… list.
  """
  @spec prose(list() | nil, [map()]) :: Phoenix.HTML.safe() | nil
  def prose(entries, references) do
    case english_entry(entries) do
      nil ->
        nil

      entry ->
        html =
          case Enum.find(entry["supportingMedia"] || [], &(&1["type"] == "text/html")) do
            %{"value" => value} -> value
            _ -> markdown(entry["value"] || "")
          end

        link_commit_shas(html, references)
    end
  end

  defp english_entry(entries) do
    entries |> List.wrap() |> Enum.find(&(&1["lang"] == "en"))
  end

  @doc "Renders a markdown string to HTML (same engine nimble_publisher uses)."
  @spec markdown(String.t()) :: String.t()
  def markdown(text) when is_binary(text) do
    MDExNative.Comrak.markdown_to_html(text,
      extension: [table: true, autolink: true, strikethrough: true],
      render: [hardbreaks: false, unsafe: true]
    )
  end

  ## ---------------------------------------------------------------- Tags

  @doc "DaisyUI badge class for a CNA tag."
  def cna_tag_class("disputed"), do: "badge-warning"
  def cna_tag_class("unsupported-when-assigned"), do: "badge-neutral"
  def cna_tag_class("exclusively-hosted-service"), do: "badge-info"
  def cna_tag_class(_other), do: "badge-ghost"

  @doc "Human label for a CNA tag (`unsupported-when-assigned` → `Unsupported when assigned`)."
  def humanize_tag(tag), do: tag |> String.replace("-", " ") |> upcase_first()

  @doc "DaisyUI badge class for a reference tag."
  def ref_tag_class("vendor-advisory"), do: "badge-warning"
  def ref_tag_class("mitigation"), do: "badge-info"
  def ref_tag_class("exploit"), do: "badge-error"
  def ref_tag_class(_other), do: "badge-ghost"

  @doc "Human label for a credit type (`remediation_developer` → `Remediation developer`)."
  def humanize_credit(type), do: type |> String.replace("_", " ") |> upcase_first()

  @doc """
  Sorts references advisory-tagged (`vendor-advisory` or `third-party-advisory`)
  first, then patch-tagged, then everything else, preserving original
  relative order within each tier (stable sort) — the References card is
  one flat list, not grouped by tag, even at 11+ rows (rev 3: the grouping
  IS the sort order; no headers).
  """
  @spec sort_references([map()]) :: [map()]
  def sort_references(references) when is_list(references) do
    Enum.sort_by(references, fn ref -> reference_tier(ref["tags"] || []) end)
  end

  defp reference_tier(tags) do
    cond do
      "vendor-advisory" in tags or "third-party-advisory" in tags -> 0
      "patch" in tags -> 1
      true -> 2
    end
  end

  @commit_url_regex ~r/^https:\/\/github\.com\/([^\/]+\/[^\/]+)\/commit\/([0-9a-f]{7,40})$/

  @doc """
  Presentation data for one References row: `%{kind:, url:, name:, owner_repo:,
  sha:, tag:, tone:, faint?:}`. The template renders the body from `kind`:

    * `:commit` — a GitHub commit URL (`github.com/owner/repo/commit/<sha>`)
      renders as `host/owner/repo · <7-char mono sha> ↗` in the text face —
      the raw URL never appears (full URL stays in `href`/`title`).
    * `:link` — everything else renders its `name` (falling back to the
      bare `url`) as the link text.

  `broken-link` rows (`faint?: true`) render faint (not struck through —
  strikethrough reads as retracted) but stay in the list and stay
  clickable. The tag pill is the FIRST tag only (`tag`/`tone`); untagged
  references get `tag: nil` — no pill, absence is honest.
  `vendor-advisory`/`third-party-advisory` are warn-toned, every other tag
  is neutral.
  """
  @spec reference_row(map()) :: map()
  def reference_row(ref) do
    tags = ref["tags"] || []
    tag = List.first(tags)
    url = ref["url"]

    body =
      case url && Regex.run(@commit_url_regex, url) do
        [_full, owner_repo, sha] -> %{kind: :commit, owner_repo: owner_repo, sha: sha}
        _no_match -> %{kind: :link, name: ref["name"] || url}
      end

    Map.merge(body, %{
      url: url,
      tag: tag,
      tone: if(tag in ["vendor-advisory", "third-party-advisory"], do: :warn, else: :neutral),
      faint?: "broken-link" in tags
    })
  end

  @doc "Component rendering a References row's body per `reference_row/1`'s `kind`."
  attr :row, :map, required: true

  def reference_body(%{row: %{kind: :commit}} = assigns) do
    ~H"""
    <a
      href={@row.url}
      title={@row.url}
      target="_blank"
      rel="noopener"
      class={["truncate", @row.faint? && "text-base-content/40"]}
    >
      github.com/{@row.owner_repo} · <code>{short_sha7(@row.sha)}</code> ↗
    </a>
    """
  end

  def reference_body(%{row: %{kind: :link}} = assigns) do
    ~H"""
    <a
      href={@row.url}
      target="_blank"
      rel="noopener"
      class={["truncate", @row.faint? && "text-base-content/40"]}
    >
      {@row.name}
    </a>
    """
  end

  defp upcase_first(""), do: ""
  defp upcase_first(<<first::utf8, rest::binary>>), do: String.upcase(<<first::utf8>>) <> rest

  ## ---------------------------------------------------------------- Affected ranges

  @doc """
  Derives the branch-label prefix for a range line (`"1.5 series"`,
  `"maint-27"`) from its FIX boundary version — the leading two dotted
  numeric components. `versionType == "otp"` (tag matching `OTP-NN.M...` or
  bare `NN.M...`) uses the `maint-<major>` shape; everything else (semver
  and semver-like git tags) uses `"<major>.<minor> series"`. Returns nil
  when no numeric components can be found — callers omit the label rather
  than render a broken prefix (and always omit it for a single-range entry).
  """
  @spec branch_label(String.t() | nil, String.t() | nil) :: String.t() | nil
  def branch_label(nil, _type), do: nil

  def branch_label(fix_version, "otp") do
    case Regex.run(~r/^(?:OTP-)?(\d+)\.(\d+)/, fix_version) do
      [_full, major, _minor] -> "maint-#{major}"
      nil -> nil
    end
  end

  def branch_label(fix_version, _type) do
    case Regex.run(~r/(\d+)\.(\d+)/, fix_version) do
      [_full, major, minor] -> "#{major}.#{minor} series"
      nil -> nil
    end
  end

  @doc """
  Derives the effective fix boundary for a `versions[]` entry: a concrete
  `lessThan`, or the LOWEST `status == "unaffected"` boundary in `changes[]`
  (a chained fix within one open range), or nil when the range is fully open
  (`lessThan == "*"` with no `changes`).

  "Fixed in" means the first safe version of the range's own line, so
  candidates are ranked by PARSED version via
  `VarselWeb.CveView.AffectedChecker`'s orderable comparison — never by
  `changes[]` array order, which real-world records don't guarantee is
  sorted (see CVE-2098-0002's OTP range, whose changes arrive
  `28.0.3, 27.3.4.3, 26.2.5.15`; the fix is 26.2.5.15, the smallest). A
  boundary that fails to parse under the entry's `versionType` (e.g. a git
  sha — shas don't order) falls back to array order among the unparseable
  ones, since there's no comparison to rank them by.
  """
  @spec fix_boundary(map()) :: String.t() | nil
  def fix_boundary(%{"lessThan" => less_than, "changes" => [_ | _] = changes} = version) when less_than == "*" do
    type = version["versionType"]

    changes
    |> Enum.filter(&(&1["status"] == "unaffected"))
    |> Enum.min_by(&AffectedChecker.parse(&1["at"], type), &orderable_or_last?/2, fn -> nil end)
    |> case do
      %{"at" => at} -> at
      nil -> nil
    end
  end

  def fix_boundary(%{"lessThan" => "*"}), do: nil
  def fix_boundary(%{"lessThan" => less_than}) when is_binary(less_than), do: less_than
  def fix_boundary(_version), do: nil

  # Comparator for `Enum.min_by/4`'s sorter: parsed versions order normally;
  # an unparseable (`:error`) boundary never outranks a parseable one, and
  # ties (both `:error`, e.g. a git range with several shas) keep the
  # earlier array position — `Enum.min_by/4` is stable, so returning `true`
  # ("a is <= b") for an `:error`/`:error` pair preserves original order.
  defp orderable_or_last?(:error, :error), do: true
  defp orderable_or_last?(:error, _b), do: false
  defp orderable_or_last?(_a, :error), do: true
  defp orderable_or_last?(a, b), do: AffectedChecker.compare(a, b) != :gt

  @doc """
  Whether a range's introduction lies wholly within the branch its fix
  belongs to (R5): the range's lower bound must share the fix's leading
  numeric component(s) — major only for OTP release lines, `{major,minor}`
  for semver-shaped versions. When the range predates the branch (its lower
  bound sits on an earlier line than the fix), the branch label is NOT a
  legitimate leading prefix for the whole range — callers move it into the
  fix note as a parenthetical instead. Bare/unparseable bounds count as "not
  within" (no leading label rather than a guessed one).
  """
  @spec range_within_branch?(String.t(), String.t(), String.t()) :: boolean()
  def range_within_branch?(lower_version, fix_version, "otp") do
    with [_, lower_major] <- Regex.run(~r/^(?:OTP-)?(\d+)/, lower_version),
         [_, fix_major] <- Regex.run(~r/^(?:OTP-)?(\d+)/, fix_version) do
      lower_major == fix_major
    else
      _no_match -> false
    end
  end

  def range_within_branch?(lower_version, fix_version, _type) do
    with [_, lower_major, lower_minor] <- Regex.run(~r/^(\d+)\.(\d+)/, lower_version),
         [_, fix_major, fix_minor] <- Regex.run(~r/^(\d+)\.(\d+)/, fix_version) do
      {lower_major, lower_minor} == {fix_major, fix_minor}
    else
      _no_match -> false
    end
  end

  @doc """
  Normalizes a raw `versions[]` list into deduped, canonical affected
  ranges — the SINGLE pipeline both the rendered range lines
  (`VarselWeb.CveHTML.affected_ranges/1`) and the checker's matcher
  (`checker_packages/1` → `AffectedChecker.match/2`) draw from, so a
  real-world record's multiple representations of the same range (a `purl`
  duplicate of a `semver` range, both alongside an unrelated `git` range)
  never double-render and never let the matcher pick a representation with
  the wrong comparison semantics.

  Per-entry, in order:

    * R1 — a `purl`-typed boundary (`pkg:hex/ash@3.5.39`) is rewritten to
      its bare version (everything after the last `@`) and reclassified as
      `"semver"` — including `pkg:otp/*` purls, whose bare numbers are the
      OTP APPLICATION's own version scheme (`3.0.1`, `5.3.3`, …), never OTP
      release tags, so they compare as plain semver, never as `"otp"`. The
      original purl-prefixed strings are kept alongside as `*_raw` for
      `title` attributes. Non-purl entries pass through unchanged (their
      `*_raw` mirrors the bare value, so callers don't need to branch).
    * R2 — entries are grouped by `{normalized_type_family, lower, fix}`
      (`type_family` collapses `semver`/`purl→semver` together but keeps
      `git`/`otp`/other types apart, since a git range is never a duplicate
      of a numeric one even if some renderer coincidentally strung together
      the same digits). Within a group, the representation that needed no
      R1 stripping is preferred (a plain `semver`/`otp` entry over its
      `purl` duplicate); ties keep the first.

  Only `status == "affected"` entries participate — this mirrors
  `affected_ranges/1`'s existing filter and is what the checker needs too.
  """
  @spec normalize_versions([map()]) :: [map()]
  def normalize_versions(versions) when is_list(versions) do
    versions
    |> Enum.filter(&(&1["status"] == "affected"))
    |> Enum.map(&normalize_entry/1)
    |> Enum.filter(& &1)
    |> dedup_normalized()
  end

  defp normalize_entry(%{"version" => version, "versionType" => "purl"} = entry) do
    case parse_purl(version || "") do
      {:ok, purl} ->
        type = purl_base_type(purl)

        Map.merge(entry, %{
          "version" => purl_bare_version(version),
          "version_raw" => version,
          "versionType" => type,
          "lessThan" => entry["lessThan"] && purl_bare_version(entry["lessThan"]),
          "lessThan_raw" => entry["lessThan"],
          "lessThanOrEqual" => entry["lessThanOrEqual"] && purl_bare_version(entry["lessThanOrEqual"]),
          "lessThanOrEqual_raw" => entry["lessThanOrEqual"],
          "changes" => normalize_changes(entry["changes"])
        })

      _error ->
        nil
    end
  end

  defp normalize_entry(%{"version" => version} = entry) do
    Map.merge(entry, %{
      "version_raw" => version,
      "lessThan_raw" => entry["lessThan"],
      "lessThanOrEqual_raw" => entry["lessThanOrEqual"],
      "changes" => normalize_changes(entry["changes"])
    })
  end

  defp normalize_entry(_entry), do: nil

  defp normalize_changes(nil), do: nil

  # R1 applies to changes[].at too — a purl-typed range's chained fixes
  # (pkg:otp/ssh@5.3.3) arrive purl-prefixed just like the top-level bounds.
  defp normalize_changes(changes) do
    Enum.map(changes, fn change ->
      change
      |> Map.put("at_raw", change["at"])
      |> Map.put("at", purl_bare_version(change["at"]))
    end)
  end

  defp purl_bare_version(purl_string) when is_binary(purl_string) do
    if String.starts_with?(purl_string, "pkg:") do
      purl_string |> String.split("@") |> List.last()
    else
      purl_string
    end
  end

  defp purl_bare_version(other), do: other

  # Every purl type's bare version compares as semver — including
  # `pkg:otp/*`, whose numbers are the OTP APPLICATION's own version scheme
  # (never OTP release tags; those only ever arrive as plain
  # `versionType: "otp"` entries, a genuinely separate representation of
  # the same real vulnerability, not a duplicate — see CVE-2098-0002's
  # shape, board addendum item 3).
  defp purl_base_type(%Purl{}), do: "semver"

  # R2: group by {type family, normalized lower, normalized fix}. `git`
  # keeps its own type as the family key (never merges with numeric
  # ranges); everything else that normalizes to "semver"/"otp" via R1
  # shares a family with its plain counterpart. Preferring the entry with
  # no `*_raw` divergence from its normalized form means a plain semver/otp
  # entry wins over its purl-derived duplicate.
  defp dedup_normalized(entries) do
    entries
    |> Enum.group_by(&dedup_key/1)
    |> Map.values()
    |> Enum.map(&Enum.min_by(&1, fn e -> if needed_normalization?(e), do: 1, else: 0 end))
    |> Enum.sort_by(fn e -> Enum.find_index(entries, &(&1 == e)) end)
  end

  defp dedup_key(entry) do
    {entry["versionType"], entry["version"], fix_boundary(entry)}
  end

  defp needed_normalization?(entry) do
    entry["version_raw"] != entry["version"] or
      entry["lessThan_raw"] != entry["lessThan"]
  end

  ## ---------------------------------------------------------------- purl helpers

  defp parse_purl(purl_string) when is_binary(purl_string) do
    purl_string |> String.split("?") |> hd() |> Purl.new()
  end

  defp parse_purl(_other), do: :error

  # Full package name including namespace, joined with "/".
  defp purl_name(%Purl{namespace: [], name: name}), do: name
  defp purl_name(%Purl{namespace: ns, name: name}), do: Enum.join(ns ++ [name], "/")

  @doc "Truncates a commit sha to its short 10-char form for display; passes non-shas through."
  @spec short_sha(String.t()) :: String.t()
  def short_sha(version) when is_binary(version), do: String.slice(version, 0, 10)
  def short_sha(version), do: version

  @doc """
  Truncates a commit sha to its short 7-char form — the site's convention
  for References-row and git-range-line sha display (rev 3, R4), distinct
  from `short_sha/1`'s 10-char form used elsewhere for git version links.
  """
  @spec short_sha7(String.t()) :: String.t()
  def short_sha7(sha) when is_binary(sha), do: String.slice(sha, 0, 7)
  def short_sha7(sha), do: sha
end
