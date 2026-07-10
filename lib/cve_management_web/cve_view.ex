# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.CveView do
  @moduledoc """
  Shared rendering helpers for CVE records — the Phoenix port of the Jekyll
  site's `package-link.html`, `version-link.html`, `link_commit_shas.rb`, and
  the per-ecosystem link derivation baked into `cve.html`.

  Functions come in two flavours:

    * plain helpers returning data (`best_cvss/1`, `severity_class/1`,
      `package_link/1` → `{label, url}`) used from templates and tests, and
    * `Phoenix.Component` function components (`package_ref/1`, `version_ref/1`)
      that render the same markup the site produced.
  """
  use Phoenix.Component

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
      Enum.find_value(metrics, fn metric ->
        case metric[key] do
          %{} = cvss -> Map.put_new(cvss, "version", version_of(key))
          _ -> nil
        end
      end)
    end)
  end

  defp version_of("cvssV4_0"), do: "4.0"
  defp version_of("cvssV3_1"), do: "3.1"
  defp version_of("cvssV3_0"), do: "3.0"

  @doc "DaisyUI badge class for a CVSS base severity."
  @spec severity_class(String.t() | nil) :: String.t()
  def severity_class("LOW"), do: "badge-success"
  def severity_class("MEDIUM"), do: "badge-warning"
  def severity_class("HIGH"), do: "badge-error"
  def severity_class("CRITICAL"), do: "badge-neutral"
  def severity_class(_none), do: "badge-ghost"

  @doc "Link to the appropriate CVSS calculator for a vector string, or nil."
  @spec cvss_calculator_url(map()) :: String.t() | nil
  def cvss_calculator_url(%{"version" => "4.0", "vectorString" => vector}),
    do: "https://nvd.nist.gov/site-scripts/cvss-v4-calculator-main/index.html##{vector}"

  def cvss_calculator_url(%{"version" => "3.1", "vectorString" => vector}),
    do: "https://chandanbn.github.io/cvss/##{vector}"

  def cvss_calculator_url(_other), do: nil

  ## ---------------------------------------------------------------- CWE / CAPEC

  @doc "The primary English CWE problemType description, or nil."
  @spec cwe_description(map()) :: map() | nil
  def cwe_description(cna) when is_map(cna) do
    cna
    |> Map.get("problemTypes", [])
    |> Enum.flat_map(&Map.get(&1, "descriptions", []))
    |> Enum.find(&(&1["lang"] == "en" and &1["type"] == "CWE" and &1["cweId"]))
  end

  @doc "CAPEC impact entries that carry a capecId."
  @spec capec_items(map()) :: [map()]
  def capec_items(cna) when is_map(cna), do: cna |> Map.get("impacts", []) |> Enum.filter(& &1["capecId"])

  @doc "MITRE definition URL for a `CWE-NNN` id."
  def cwe_url("CWE-" <> number), do: "https://cwe.mitre.org/data/definitions/#{number}.html"

  @doc "MITRE definition URL for a `CAPEC-NNN` id."
  def capec_url("CAPEC-" <> number), do: "https://capec.mitre.org/data/definitions/#{number}.html"

  @doc "First English description of a CAPEC impact entry."
  def capec_text(impact) do
    impact
    |> Map.get("descriptions", [])
    |> Enum.find_value(fn d -> if d["lang"] == "en", do: d["value"] end)
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

  defp upcase_first(""), do: ""
  defp upcase_first(<<first::utf8, rest::binary>>), do: String.upcase(<<first::utf8>>) <> rest

  ## ---------------------------------------------------------------- purl helpers

  defp parse_purl(purl_string) when is_binary(purl_string) do
    purl_string |> String.split("?") |> hd() |> Purl.new()
  end

  defp parse_purl(_other), do: :error

  # Full package name including namespace, joined with "/".
  defp purl_name(%Purl{namespace: [], name: name}), do: name
  defp purl_name(%Purl{namespace: ns, name: name}), do: Enum.join(ns ++ [name], "/")

  defp short_sha(version) when is_binary(version), do: String.slice(version, 0, 10)
  defp short_sha(version), do: version
end
