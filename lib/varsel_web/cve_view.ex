# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveView do
  @moduledoc """
  Shared rendering helpers for CVE records — the Phoenix port of the Jekyll
  site's `package-link.html`, `version-link.html`, and the per-ecosystem link
  derivation baked into `cve.html`.

  Functions come in two flavours:

    * plain helpers returning data (`best_cvss/1`,
      `package_link/1` → `{label, url}`) used from templates and tests, and
    * `Phoenix.Component` function components (`package_display_name/1`,
      `version_ref/1`) that render the same markup the site produced.
  """
  use Phoenix.Component

  alias Phoenix.HTML.Engine
  alias VarselWeb.CveView.AffectedChecker

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

  @doc """
  A CVE title split for wrapping at underscores via `<wbr>`: the raw title
  segments interspersed with a `raw/1`'d `_<wbr>`. HEEx escapes the bare title
  segments on render, so `raw/1` only ever touches the fixed literal and a
  title carrying markup renders as inert text.
  """
  @spec wrap_title(String.t()) :: Phoenix.HTML.Safe.t()
  def wrap_title(title) when is_binary(title) do
    title
    |> String.split("_")
    |> Enum.intersperse(Phoenix.HTML.raw("_<wbr>"))
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
  def package_link(%{"packageURL" => package_url} = entry) when not is_nil(package_url) do
    case Purl.new!(package_url) do
      %Purl{type: "hex"} = purl ->
        name = purl_name(purl)
        {"pkg:hex/#{name}", "https://hex.pm/packages/#{name}"}

      %Purl{type: "npm"} = purl ->
        name = purl_name(purl)
        {"pkg:npm/#{name}", "https://www.npmjs.com/package/#{name}"}

      %Purl{type: "github"} = purl ->
        path = purl_name(purl)
        {"pkg:github/#{path}", "https://github.com/#{path}"}

      %Purl{type: "oci"} = purl ->
        oci_link(entry, purl)

      purl ->
        {Purl.to_string(%{purl | version: nil, qualifiers: %{}, subpath: []}), nil}
    end
  end

  def package_link(entry) when is_map(entry) do
    {"#{entry["vendor"]} / #{entry["product"]}", nil}
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
  def registry_link(%{"packageURL" => package_url} = entry) when not is_nil(package_url) do
    case Purl.new!(package_url) do
      %Purl{type: "hex"} = purl ->
        {"Hex.pm", "https://hex.pm/packages/#{purl_name(purl)}"}

      %Purl{type: "npm"} = purl ->
        {"npm", "https://www.npmjs.com/package/#{purl_name(purl)}"}

      %Purl{type: "oci"} = purl ->
        oci_registry_link(entry, purl)

      _other ->
        nil
    end
  end

  def registry_link(_entry), do: nil

  defp oci_registry_link(entry, purl) do
    case oci_link(entry, purl) do
      {_label, url} when is_binary(url) -> {"Container registry", url}
      _no_link -> nil
    end
  end

  @doc """
  Renders an affected package's `versions[]` — one line per entry, as
  `VarselWeb.CveHTML.affected_ranges/1` shapes them.

  A line shows the interval the entry asserts and the status it asserts for it,
  coloured by that status: affected red, unaffected green, unknown amber. The
  record's own claim is what prints, never a derived one — an `unaffected` or
  `unknown` entry is as real as an affected one and reads differently.

  An entry with `changes[]` lists its transitions beneath it, in the order the
  record gives them, each carrying the status it switches to. That is the order
  the resolution algorithm applies, so it is the order that explains the result.

  `default_status` closes the block: whatever no entry covers takes it, which is
  half of what the record says and is otherwise invisible.

  The branch label ("1.19 series") sits in a reserved column so every line's
  bound starts at the same x; the column disappears when no line has one.
  """
  attr :ranges, :list, required: true, doc: "rows from `VarselWeb.CveHTML.affected_ranges/1`"
  attr :default_status, :string, default: nil, doc: "the entry's `defaultStatus`"

  attr :class, :any,
    default: nil,
    doc: "placement and type-scale extras, e.g. a denser workspace list"

  def affected_range_list(assigns) do
    assigns = assign(assigns, :labelled?, Enum.any?(assigns.ranges, & &1.branch_label))

    ~H"""
    <div class={["flex flex-col gap-1 font-mono text-sm", @class]}>
      <div :for={range <- @ranges}>
        <div>
          <span
            :if={@labelled?}
            class="mr-2 inline-block w-16 text-right font-sans text-xs text-base-content/50"
          >
            {range.branch_label}
          </span>
          <%!-- A single-version entry names one version, so it takes no operator. --%>
          <span :if={range.single?} title={range.lower_title} class={status_tone(range.status)}>
            {display(range, range.lower)}
          </span>
          <span :if={not range.single? and range.lower}>
            <span class="text-base-content/60">≥</span>
            <span title={range.lower_title} class={status_tone(range.status)}>
              {display(range, range.lower)}
            </span>
          </span>
          <span :if={range.upper}>
            <span class="text-base-content/60">{if range.upper_inclusive?, do: "≤", else: "<"}</span>
            <span title={range.upper_title} class={status_tone(upper_status(range))}>
              {display(range, range.upper)}
            </span>
          </span>
          <span :if={range.open?} class="text-base-content/60">and up</span>
          <span class={["ml-1 font-sans text-sm", status_tone(range.status)]}>
            {status_word(range.status)}
          </span>
        </div>
        <%!-- Transitions read as a continuation of the line above them. --%>
        <div :for={change <- range.changes} class="pl-6">
          <span class="text-base-content/60">→</span>
          <span title={change.at_title} class={status_tone(change.status)}>
            {display(range, change.at)}
          </span>
          <span class={["ml-1 font-sans text-sm", status_tone(change.status)]}>
            {status_word(change.status)}
          </span>
        </div>
      </div>
      <div :if={@default_status} class="font-sans text-sm text-base-content/60">
        every other version:
        <span class={status_tone(default_tone(@default_status))}>{@default_status}</span>
      </div>
    </div>
    """
  end

  # An exclusive `<` bound is the first version OUTSIDE the span, so it carries
  # the status that follows, not the one that ends there — the version you
  # upgrade to, in the colour of what it gets you. An inclusive `≤` bound is
  # still inside the span and keeps the entry's own status.
  #
  # What follows is the record's own `defaultStatus` when nothing else covers
  # it; the block passes that down so the bound never guesses.
  defp upper_status(%{upper_inclusive?: true, status: status}), do: status
  defp upper_status(%{after_status: nil}), do: :neutral
  defp upper_status(%{after_status: after_status}), do: after_status

  # One colour per status, everywhere it appears — a bound, a transition, or the
  # default line. Amber for unknown is deliberate: it is neither safe nor unsafe.
  # A bound we could not resolve (a commit sha, an unorderable scheme) takes no
  # colour rather than a guessed one.
  defp status_tone(:neutral), do: "text-base-content/70"
  defp status_tone(:affected), do: "text-error"
  defp status_tone(:unaffected), do: "text-success"
  defp status_tone(:unknown), do: "text-warning"

  defp status_word(:affected), do: "affected"
  defp status_word(:unaffected), do: "not affected"
  defp status_word(:unknown), do: "status unknown"

  defp default_tone("affected"), do: :affected
  defp default_tone("unaffected"), do: :unaffected
  defp default_tone(_unknown_or_absent), do: :unknown

  # Commit shas shorten to the 7 characters git itself abbreviates to; version
  # strings print as they are.
  defp display(%{kind: :git}, value), do: short_sha7(value)
  defp display(_range, value), do: value

  @doc """
  The bare package name for an affected entry (`bandit`, `erlang/otp`, no
  `pkg:type/` prefix), for spots that need a short name over the full
  purl chip label (the checker's placeholder and verdict copy: `bandit
  version, e.g. …`, `✗ cowlib 2.11.0 is affected`). Falls back to
  `vendor/product` when there's no parseable purl.
  """
  @spec bare_package_name(map()) :: String.t()
  def bare_package_name(%{"packageURL" => package_url}) do
    package_url
    |> Purl.new!()
    |> purl_name()
  end

  def bare_package_name(entry) when is_map(entry) do
    "#{entry["vendor"]}/#{entry["product"]}"
  end

  @doc """
  Whether an affected entry's package is an OTP application (`pkg:otp/*`
  purl type). This drives the checker's vocabulary: a `pkg:otp/*` package
  speaks in application versions even when its ranges are `semver`-typed, an
  OTP app version with no release mapping.
  """
  @spec otp_package?(map()) :: boolean()
  def otp_package?(%{"packageURL" => package_url}) do
    match?(%Purl{type: "otp"}, Purl.new!(package_url))
  end

  def otp_package?(_entry), do: false

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

  def version_link(version, "semver", %{"packageURL" => package_url}) do
    case Purl.new!(package_url) do
      %Purl{type: "hex"} = purl ->
        {version, "https://hex.pm/packages/#{purl_name(purl)}/#{version}"}

      _other ->
        {version, nil}
    end
  end

  def version_link(version, _type, entry) do
    with purl_string when is_binary(purl_string) <- entry["packageURL"],
         true <-
           String.contains?(purl_string, "pkg:oci/") and String.contains?(purl_string, "ghcr.io") do
      purl = Purl.new!(purl_string)
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
    <.link :if={@linked?} href={@url} target="_blank" rel="noopener"><code>{@label}</code></.link>
    <code :if={not @no_fix? and not @linked?}>{@label}</code>
    """
  end

  ## ---------------------------------------------------------------- Markdown

  # Richest first: markdown carries the most formatting we can render, html is
  # taken as-is, and plain text goes through markdown too so paragraphs and
  # autolinks still come out.
  @media_priority ["text/markdown", "text/html", "text/plain"]

  @doc """
  Renders advisory prose from the English entry's `supportingMedia`, preferring
  #{Enum.map_join(@media_priority, ", ", &"`#{&1}`")} in that order and falling
  back to the entry's own markdown `value`. `entries` is a
  `descriptions`/`workarounds`/… list.
  """
  # Every branch sanitizes.
  # sobelow_skip ["XSS.Raw"]
  @spec prose(list() | nil) :: Phoenix.HTML.safe() | nil
  def prose(entries) do
    case english_entry(entries) do
      nil -> nil
      entry -> entry |> render_prose() |> Phoenix.HTML.raw()
    end
  end

  defp render_prose(entry) do
    media = List.wrap(entry["supportingMedia"])

    Enum.find_value(@media_priority, fn type ->
      case Enum.find(media, &(&1["type"] == type)) do
        nil -> nil
        found -> found |> media_value() |> render_media(type)
      end
    end) || markdown(entry["value"] || "")
  end

  # `markdown/1` sanitizes its own output; supportingMedia may come straight
  # from a MITRE import, so the html branch has to.
  defp render_media(nil, _type), do: nil
  defp render_media(value, "text/html"), do: MDExNative.Ammonia.safe_html(value)
  defp render_media(value, _markdown_or_plain), do: markdown(value)

  # Undecodable base64 falls through to the next media type rather than
  # rendering the encoded value as prose.
  defp media_value(%{"base64" => true, "value" => value}) when is_binary(value) do
    case Base.decode64(value, ignore: :whitespace) do
      {:ok, decoded} -> decoded
      :error -> nil
    end
  end

  defp media_value(%{"value" => value}) when is_binary(value), do: value
  defp media_value(_media), do: nil

  defp english_entry(entries) do
    entries |> List.wrap() |> Enum.find(&(&1["lang"] == "en"))
  end

  @doc """
  Renders a markdown string to HTML.

  `unsafe: true` passes literal HTML through Comrak; `sanitize` then strips
  scripts and dangerous attributes so the result is safe for `raw/1`.
  """
  @spec markdown(String.t()) :: String.t()
  def markdown(text) when is_binary(text) do
    MDExNative.Comrak.markdown_to_html(text,
      extension: [table: true, autolink: true, strikethrough: true],
      render: [hardbreaks: false, unsafe: true],
      sanitize: MDEx.Document.default_sanitize_options()
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

  @doc "Human label for a credit type (`remediation_developer` → `Remediation developer`)."
  def humanize_credit(type), do: type |> String.replace("_", " ") |> upcase_first()

  @doc """
  Groups `credits[]` into one entry per person: `{value, [type]}`, in order of
  first appearance, with each person's types deduplicated. A record commonly
  credits the same person under several roles (finder and remediation
  developer, say), which would otherwise render them once per role.
  """
  @spec credit_roles([map()]) :: [{String.t(), [String.t()]}]
  def credit_roles(credits) when is_list(credits) do
    credits
    |> Enum.group_by(& &1["value"], & &1["type"])
    |> Enum.map(fn {value, types} -> {value, types |> Enum.reject(&is_nil/1) |> Enum.uniq()} end)
    |> Enum.sort_by(fn {value, _types} ->
      Enum.find_index(credits, &(&1["value"] == value))
    end)
  end

  @doc """
  Sorts references advisory-tagged (`vendor-advisory` or `third-party-advisory`)
  first, then patch-tagged, then everything else, preserving original
  relative order within each tier (stable sort). The References card is one
  flat list at any length: the sort order is the grouping, and there are no
  headers.
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
  @ghsa_url_regex ~r/^https:\/\/github\.com\/([^\/]+\/[^\/]+)\/security\/advisories\/(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$/
  @osv_url_regex ~r/^https:\/\/osv\.dev\/vulnerability\/([A-Za-z0-9][A-Za-z0-9.-]*)$/

  # The tag pill beside a reference: a hairline outline, warn-toned for the
  # advisory tags and muted otherwise. Outlined rather than a filled badge so a
  # list of references reads as links first and tags second.
  attr :tag, :string, required: true

  defp reference_tag(assigns) do
    assigns = assign(assigns, :warn?, assigns.tag in ["vendor-advisory", "third-party-advisory"])

    ~H"""
    <span class={[
      "flex-shrink-0 rounded-[5px] border px-[0.4rem] py-[0.05rem] text-[0.68rem] whitespace-nowrap",
      if(@warn?,
        do: "border-warning/40 text-warning",
        else: "border-base-300/70 text-base-content/50"
      )
    ]}>
      {@tag}
    </span>
    """
  end

  @doc """
  One reference: a link followed by its tag pills, the URL's shape deciding
  how the link reads:

    * a GitHub commit (`github.com/owner/repo/commit/<sha>`) →
      `github.com/owner/repo · <7-char mono sha> ↗`, the raw URL never shown
    * a GitHub Security Advisory → `github.com/owner/repo · <mono GHSA id> ↗`,
      the same shape: the identifier is what a reader recognises, not the path
      to it
    * an OSV entry (`osv.dev/vulnerability/<id>`) → `osv.dev · <mono id> ↗`
    * anything else → the bare URL, or `name` when one is given

  Those identifier forms carry the full URL as a `title`, since their text
  deliberately hides it; a plain link already reads as its own URL. A
  `broken-link` tag renders the row faint, keeping it listed and clickable.
  Struck through it would read as retracted.

  `pills` picks how many tags are drawn — `:first` (the default) is the
  published card's flat one-pill-per-row look, `:all` suits an editor that
  should show everything a row actually carries.
  """
  attr :url, :string, required: true
  attr :tags, :list, default: []
  attr :name, :string, default: nil, doc: "link text, overriding what the URL would render as"
  attr :pills, :atom, values: [:first, :all], default: :first

  def reference(assigns) do
    assigns =
      assign(
        assigns,
        :pill_tags,
        if(assigns.pills == :all, do: assigns.tags, else: Enum.take(assigns.tags, 1))
      )

    ~H"""
    <span class="min-w-0 grow basis-auto break-words">
      <.reference_body url={@url} tags={@tags} name={@name} />
    </span>
    <span :if={@pill_tags != []} class="flex shrink-0 items-center gap-1">
      <.reference_tag :for={tag <- @pill_tags} tag={tag} />
    </span>
    """
  end

  attr :url, :string, required: true
  attr :tags, :list, default: []
  attr :name, :string, default: nil

  defp reference_body(assigns) do
    assigns = assign(assigns, :shape, reference_shape(assigns.url, assigns.name))

    ~H"""
    <.link
      href={@url}
      title={@shape.kind != :link && @url}
      target="_blank"
      rel="noopener"
      class={["broken-link" in @tags && "text-base-content/40"]}
    >
      <%= case @shape do %>
        <% %{kind: :commit, owner_repo: owner_repo, sha: sha} -> %>
          github.com/{owner_repo} · <code>{short_sha7(sha)}</code> ↗
        <% %{kind: :ghsa, owner_repo: owner_repo, id: id} -> %>
          github.com/{owner_repo} · <code>{id}</code> ↗
        <% %{kind: :osv, id: id} -> %>
          osv.dev · <code>{id}</code> ↗
        <% %{kind: :link, name: name} -> %>
          {name}
      <% end %>
    </.link>
    """
  end

  # How a reference URL reads: a named link wins outright, otherwise the URL
  # shape decides whether an identifier or the bare link is the honest face.
  defp reference_shape(_url, name) when is_binary(name), do: %{kind: :link, name: name}
  defp reference_shape(nil, _name), do: %{kind: :link, name: nil}

  defp reference_shape(url, _name) do
    cond do
      match = Regex.run(@commit_url_regex, url) ->
        [_full, owner_repo, sha] = match
        %{kind: :commit, owner_repo: owner_repo, sha: sha}

      match = Regex.run(@ghsa_url_regex, url) ->
        [_full, owner_repo, id] = match
        %{kind: :ghsa, owner_repo: owner_repo, id: id}

      match = Regex.run(@osv_url_regex, url) ->
        [_full, id] = match
        %{kind: :osv, id: id}

      true ->
        %{kind: :link, name: url}
    end
  end

  defp upcase_first(""), do: ""
  defp upcase_first(<<first::utf8, rest::binary>>), do: String.upcase(<<first::utf8>>) <> rest

  ## ---------------------------------------------------------------- Affected ranges

  @doc """
  Derives the branch-label prefix for a range line (`"1.5 series"`,
  `"maint-27"`) from the leading two dotted numeric components of its FIX
  boundary version. `versionType == "otp"` (tag matching `OTP-NN.M...` or
  bare `NN.M...`) uses the `maint-<major>` shape; everything else (semver
  and semver-like git tags) uses `"<major>.<minor> series"`. Returns nil
  when no numeric components can be found, and callers then omit the label.
  They always omit it for a single-range entry.
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
  `VarselWeb.CveView.AffectedChecker`'s orderable comparison, never by
  `changes[]` array order, which real-world records don't guarantee is
  sorted (see CVE-2098-0002's OTP range, whose changes arrive
  `28.0.3, 27.3.4.3, 26.2.5.15`; the fix is 26.2.5.15, the smallest). A
  boundary that fails to parse under the entry's `versionType`, such as a
  commit sha, falls back to array order among the unparseable ones, since
  there is no comparison to rank them by.
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

  @doc """
  *Every* fix boundary of a range.

  `fix_boundary/1` answers "the first safe version of this line" — the right
  question only when the range describes one line. A `changes[]` chain does not:
  it is an open range carrying a fix per release line (the legacy shape, and
  what a git range always looks like), and every one of those fixes is real.
  Reducing them to the lowest would silently drop the rest, understating the
  affected span, so anything rendering a whole range asks this instead.

  Orderable boundaries come back sorted, so a record whose `changes[]` arrive
  shuffled (CVE-2098-0002's OTP range: `28.0.3, 27.3.4.3, 26.2.5.15`) still
  reads low-to-high. Commit shas have no order and keep their record order.
  """
  @spec fix_boundaries(map()) :: [String.t()]
  def fix_boundaries(%{"lessThan" => "*", "changes" => [_ | _] = changes} = version) do
    type = version["versionType"]

    changes
    |> Enum.filter(&is_binary(&1["at"]))
    |> Enum.sort_by(&AffectedChecker.parse(&1["at"], type), &orderable_or_last?/2)
    |> Enum.map(&{&1["at"], boundary_status(&1["status"])})
  end

  def fix_boundaries(version) do
    case fix_boundary(version) do
      nil -> []
      # A plain upper bound ends the entry's own span, so what lies at or above
      # it is not this entry's business — `nil` status, rendered neutrally.
      boundary -> [{boundary, nil}]
    end
  end

  defp boundary_status("affected"), do: :affected
  defp boundary_status("unknown"), do: :unknown
  defp boundary_status(_unaffected), do: :unaffected

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
  belongs to: the range's lower bound must share the fix's leading numeric
  component(s), major only for OTP release lines and `{major, minor}` for
  semver-shaped versions. A range whose lower bound sits on an earlier line
  than its fix spans more than that branch, so the branch label is not a
  legitimate leading prefix for it; callers move the label into the fix note
  as a parenthetical. Bare or unparseable bounds count as "not within".
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
  Normalizes a raw `versions[]` list into deduped affected ranges: the single
  pipeline both the rendered range lines (`VarselWeb.CveHTML.affected_ranges/1`)
  and the checker's matcher (`checker_packages/1` to `AffectedChecker.match/2`)
  draw from, so a record stating one range twice never double-renders.

  Each entry keeps its bounds as `*_raw` for `title` attributes. A purl-typed
  `changes[].at` (`pkg:otp/ssh@5.3.3`) is reduced to its bare version, since a
  chained fix arrives purl-prefixed just like the bounds. Entries sharing
  `{versionType, version, fix_boundary}` collapse to the first.

  Every row survives, whatever its status: under the CVE resolution algorithm an
  `unaffected` or `unknown` row is a real answer for the versions it covers.
  """
  @spec normalize_versions([map()]) :: [map()]
  def normalize_versions(versions) when is_list(versions) do
    versions
    |> Enum.map(&normalize_entry/1)
    |> Enum.filter(& &1)
    |> dedup_normalized()
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

  # Canonical versions always carry a LIST — a nil here once leaked into
  # Enum.filter via Map.get's default (which only applies to absent keys).
  defp normalize_changes(nil), do: []

  # A purl-typed range's chained fixes (`pkg:otp/ssh@5.3.3`) arrive
  # purl-prefixed just like its top-level bounds.
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

  # A git range is never a duplicate of a numeric one, even where a renderer
  # coincidentally strung together the same digits, so the type is part of the
  # key.
  defp dedup_normalized(entries) do
    Enum.uniq_by(entries, &dedup_key/1)
  end

  defp dedup_key(entry) do
    {entry["versionType"], entry["version"], fix_boundary(entry)}
  end

  @doc """
  A package's name as a reader recognises it, from its purl alone.

  Tables list packages by purl, which spends most of its width on syntax: of
  `pkg:hex/plug` only `plug` is the package, and
  `pkg:otp/ssh?repository_url=https:%2F%2Fgithub.com%2Ferlang%2Fotp&vcs_url=…`
  runs past 100 characters to say "ssh". This names the ecosystem and the
  package instead (`Hex / plug`, `Erlang / ssh`, `GitHub / erlang/otp`), and
  keeps the full purl in a `title` for anyone who needs it.

  The ecosystem is what a reader knows the package by, not the purl's type: an
  OTP application from the erlang/otp repository is Erlang's, while one from
  elixir-lang/elixir is Elixir's, and the same `pkg:otp` type covers both.

  Shortening is strictly whitelisted, and a purl that does not match a rule
  prints verbatim — better a long name than a wrong one. `package_name/1`
  carries the rules; this only renders them.
  """
  attr :purl, :string, required: true

  attr :link, :boolean,
    default: false,
    doc: "link to the package's registry page, when it has one"

  attr :class, :any, default: nil

  attr :fallback, :string,
    default: nil,
    doc: "name for an entry with no purl at all, e.g. a hosted service's vendor/product"

  def package_display_name(assigns) do
    {_label, url} = package_link(%{"packageURL" => assigns.purl})

    assigns =
      assign(assigns,
        parts: package_name(assigns.purl, assigns.fallback),
        url: assigns.link && url
      )

    ~H"""
    <.link :if={@url} href={@url} target="_blank" rel="noopener" class={@class} title={@purl}>
      <.package_parts parts={@parts} />
    </.link>
    <span :if={!@url} class={@class} title={@purl}>
      <.package_parts parts={@parts} />
    </span>
    """
  end

  attr :parts, :map, required: true

  defp package_parts(assigns) do
    ~H"""
    <span :if={@parts.ecosystem} class="text-base-content/50">{@parts.ecosystem} / </span>{@parts.name}
    """
  end

  @doc """
  Splits a purl into `%{ecosystem: name | nil, name: String.t()}` for display.

  `ecosystem` is nil when the name stands on its own — either because the purl
  names an ecosystem rather than a package (`pkg:sid/gleam.run/gleam` is just
  "Gleam"), or because nothing matched and `name` is the untouched purl.
  """
  @spec package_name(String.t() | nil, String.t() | nil) :: %{
          ecosystem: String.t() | nil,
          name: String.t()
        }
  def package_name(purl, fallback \\ nil)

  # A hosted service has no package to name — the caller's vendor/product is all
  # there is to say.
  def package_name(nil, fallback), do: fallback(fallback || "")

  def package_name(purl, _fallback) when is_binary(purl) do
    purl |> Purl.new!() |> display_parts() || fallback(purl)
  end

  defp fallback(purl), do: %{ecosystem: nil, name: to_string(purl)}

  # `nil` from any clause means "no rule matched" and falls back to the purl.

  # A hex package shortens only when nothing qualifies where it came from: a
  # namespace or a `repository_url` means some other registry, and "Hex / plug"
  # would then name the wrong one.
  defp display_parts(%Purl{type: "hex", namespace: [], name: name, qualifiers: q}) when q == %{} do
    %{ecosystem: "Hex", name: name}
  end

  # `pkg:otp` covers every OTP application, whoever ships it, so the repository
  # it comes from is what names the ecosystem.
  defp display_parts(%Purl{type: "otp", namespace: [], name: name} = purl) do
    case repository(purl) do
      "github.com/erlang/otp" -> %{ecosystem: "Erlang", name: name}
      "github.com/elixir-lang/elixir" -> elixir_parts(name)
      "github.com/erlang/rebar3" -> %{ecosystem: nil, name: "rebar3"}
      # Both ship an OTP application whose own name says too little: `hex` is
      # the Mix task, not the registry, and `nerves_hub` is the device service.
      "github.com/hexpm/hex" -> %{ecosystem: nil, name: "Hex Mix Integration"}
      "github.com/nerves-hub/nerves_hub_web" -> %{ecosystem: nil, name: "Nerves Hub"}
      _unknown_repository -> nil
    end
  end

  # An org is what tells four forks of the same project apart (esaml has four),
  # so a github purl keeps `owner/repo` whole.
  defp display_parts(%Purl{type: "github", namespace: [owner], name: name}) do
    %{ecosystem: "GitHub", name: owner <> "/" <> name}
  end

  defp display_parts(%Purl{type: "npm", namespace: [], name: name}) do
    %{ecosystem: "npm", name: name}
  end

  # An image name alone is not an address — any registry could host a `gleam`.
  # `repository_url` holds the rest, so the host names the ecosystem and its
  # path joins the image, spelling out what you would actually pull.
  defp display_parts(%Purl{type: "oci", namespace: [], name: name} = purl) do
    case purl |> repository() |> split_registry() do
      {host, path} -> %{ecosystem: host, name: path <> "/" <> name}
      nil -> nil
    end
  end

  # A software id names a project, not a package within one, so it reads as the
  # project alone. Whitelisted per purl — there is no general rule for a domain.
  defp display_parts(%Purl{type: "sid", namespace: ["erlang.org"], name: "otp"}) do
    %{ecosystem: nil, name: "Erlang"}
  end

  defp display_parts(%Purl{type: "sid", namespace: ["gleam.run"], name: "gleam"}) do
    %{ecosystem: nil, name: "Gleam"}
  end

  defp display_parts(_unrecognised), do: nil

  # Elixir ships as OTP applications; `elixir` itself is the language, the rest
  # (mix, ex_unit, …) are applications within it.
  defp elixir_parts("elixir"), do: %{ecosystem: nil, name: "Elixir"}
  defp elixir_parts(name), do: %{ecosystem: "Elixir", name: name}

  # A registry reference into its host and the path beneath it; `nil` when
  # there is no path to speak of, since the host alone locates nothing.
  defp split_registry(nil), do: nil

  defp split_registry(reference) do
    case String.split(reference, "/", parts: 2) do
      [host, path] when path != "" -> {host, path}
      _host_only -> nil
    end
  end

  # The repository a purl came from, reduced to host and path so the same repo
  # matches however it was spelled — `hexpm/hex` and `hexpm/hex.git` are one.
  defp repository(%Purl{qualifiers: qualifiers}) do
    case qualifiers["repository_url"] do
      nil ->
        nil

      url ->
        url
        |> String.replace(~r{^[a-z+]+://}, "")
        |> String.replace_suffix(".git", "")
        |> String.trim_trailing("/")
    end
  end

  ## ---------------------------------------------------------------- purl helpers

  # Full package name including namespace, joined with "/".
  defp purl_name(%Purl{namespace: [], name: name}), do: name
  defp purl_name(%Purl{namespace: ns, name: name}), do: Enum.join(ns ++ [name], "/")

  @doc "Truncates a commit sha to its short 10-char form for display; passes non-shas through."
  @spec short_sha(String.t()) :: String.t()
  def short_sha(version) when is_binary(version), do: String.slice(version, 0, 10)
  def short_sha(version), do: version

  @doc """
  Truncates a commit sha to its short 7-char form, the site's convention for
  References-row and git-range-line sha display. `short_sha/1`'s 10-char form
  is what git version links use.
  """
  @spec short_sha7(String.t()) :: String.t()
  def short_sha7(sha) when is_binary(sha), do: String.slice(sha, 0, 7)
  def short_sha7(sha), do: sha
end
