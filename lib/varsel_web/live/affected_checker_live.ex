# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AffectedCheckerLive do
  @moduledoc """
  The public CVE detail page's "Am I affected?" checker — a small LiveView
  mounted into the dead controller-rendered page (`cve_html/show.html.heex`)
  via `live_render/3`, since the page itself needs no other interactivity.

  This module only renders. The answer comes from
  `Varsel.CVE.VersionResolution`, which implements the resolution algorithm CVE
  Record Format 5.1 specifies, against the SAME `versions[]` the page's Affected
  cards render — no separate data source and no second interpretation of the
  record.

  A package carries `"askable?"`: whether its versions can be ordered at all.
  False for a product versioned by commit sha or another scheme with no
  comparison, and then no input is offered — the ranges are shown instead, since
  a typed version could never be placed against them.

  The verdict is the record's own status for that version — affected,
  unaffected, or unknown. `unknown` is a real answer, rendered neither red nor
  green: the record does not say, and dressing that as safe would be a guess.

  ## Session payload

  `live_render/3`'s session must be JSON-safe, so the mount receives one map
  per package rather than the raw CNA `affected[]` structs — see
  `VarselWeb.CveHTML.checker_packages/1` for the shape.
  """
  use VarselWeb, :live_view

  import VarselWeb.CveHTML, only: [affected_ranges: 1]

  import VarselWeb.CveView,
    only: [affected_range_list: 1, package_display_name: 1, package_name: 2]

  alias Varsel.CVE.VersionResolution

  @impl Phoenix.LiveView
  def mount(_params, %{"packages" => packages}, socket) do
    {:ok,
     socket
     |> assign(packages: packages, selected_index: 0, input: "")
     |> assign_verdict()}
  end

  @impl Phoenix.LiveView
  def handle_event("check", %{"version" => version}, socket) do
    {:noreply, socket |> assign(input: version) |> assign_verdict()}
  end

  def handle_event("select-package", %{"index" => index}, socket) do
    {:noreply,
     socket
     # keeps the typed input value across a package switch — only the
     # ranges/placeholder/verdict swap
     |> assign(selected_index: String.to_integer(index))
     |> assign_verdict()}
  end

  defp assign_verdict(socket) do
    package = Enum.at(socket.assigns.packages, socket.assigns.selected_index)

    assign(socket, package: package, verdict: resolve(package, socket.assigns.input))
  end

  # An <option> renders text, not markup, so the component's parts are joined
  # by hand here.
  defp package_option_label(package) do
    case package_name(package["purl"], package["package_fallback"]) do
      %{ecosystem: nil, name: name} -> name
      %{ecosystem: ecosystem, name: name} -> "#{ecosystem} / #{name}"
    end
  end

  # `nil` (rather than a verdict) until something is typed — an empty box is
  # not a question, so it gets the prompt instead of an answer.
  defp resolve(_package, ""), do: nil

  defp resolve(package, input) do
    if otp?(package) and r_series?(input) do
      {:error, :r_series}
    else
      VersionResolution.resolve(package["versions"], package["default_status"], input)
    end
  end

  defp otp?(package), do: package["otp_release?"] or package["otp_package?"]

  # Only an OTP checker can be asked about an R release; elsewhere a leading `R`
  # is just an unrecognizable version.
  defp r_series?(input) do
    input
    |> String.trim()
    |> String.replace_prefix("OTP-", "")
    |> String.replace_prefix("OTP_", "")
    |> then(&Regex.match?(~r/\AR\d/, &1))
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div>
      <div
        :if={length(@packages) > 1 and length(@packages) <= 4}
        class="mb-2.5 flex flex-wrap gap-1.5"
      >
        <button
          :for={{pkg, index} <- Enum.with_index(@packages)}
          type="button"
          phx-click="select-package"
          phx-value-index={index}
          class={[
            "rounded-full border px-2.5 py-0.5 font-mono text-[0.71rem] whitespace-nowrap",
            if(index == @selected_index,
              do: "border-primary bg-primary/15 text-base-content",
              else: "border-base-300/70 bg-base-100 text-base-content/70"
            )
          ]}
        >
          <.package_display_name purl={pkg["purl"]} fallback={pkg["package_fallback"]} />
        </button>
      </div>

      <form
        :if={length(@packages) > 4}
        id="checker-package-select"
        class="mb-2.5"
        phx-change="select-package"
      >
        <select name="index" class="select select-sm w-full max-w-xs font-mono text-xs">
          <option
            :for={{pkg, index} <- Enum.with_index(@packages)}
            value={index}
            selected={index == @selected_index}
          >
            {package_option_label(pkg)}
          </option>
        </select>
      </form>

      <.package_body input={@input} package={@package} verdict={@verdict} />
    </div>
    """
  end

  attr :input, :string, required: true
  attr :package, :map, required: true
  attr :verdict, :any, required: true

  defp package_body(%{package: %{"askable?" => true}} = assigns) do
    ~H"""
    <div class="flex flex-wrap items-center gap-2.5">
      <%!-- Password managers read a lone text input in a <form> as a
            credential field and offer to fill it; each vendor needs its own
            opt-out - 1Password, LastPass, Bitwarden, Dashlane in order.
            Safari ignores all of them (and `autocomplete="url"`, tried and
            dropped) - its trigger is the wording, see `checker_placeholder/1`. --%>
      <form id="checker-version-input" phx-change="check" phx-submit="check">
        <input
          type="text"
          name="version"
          value={@input}
          phx-debounce="200"
          placeholder={checker_placeholder(@package)}
          class="input input-sm w-full font-mono text-[0.71rem] sm:w-72"
          autocomplete="off"
          data-1p-ignore
          data-lpignore="true"
          data-bwignore
          data-form-type="other"
        />
      </form>
      <.verdict input={@input} package={@package} verdict={@verdict} />
    </div>
    """
  end

  # Nothing here can be ordered - a product versioned by commit sha, or by a
  # scheme with no comparison. There is no version to type, so the ranges
  # themselves are the answer, shown through the same block the Affected card
  # renders rather than restated in the checker's words.
  defp package_body(assigns) do
    assigns = assign(assigns, :ranges, affected_ranges(assigns.package))

    ~H"""
    <div class="text-sm">
      <p class="mb-1.5">
        This record states its affected versions in a form that can't be compared automatically.
      </p>
      <.affected_range_list
        :if={@ranges != []}
        ranges={@ranges}
        default_status={@package["default_status"]}
      />
    </div>
    """
  end

  # The version input's placeholder speaks OTP-release vocabulary whenever
  # the checkable ranges are OTP release tags; an OTP package whose ranges
  # are plain semver (an application version with no release mapping)
  # falls back to app-version vocabulary. Never mixed within one checker.
  #
  # Says "Erlang", never a bare "OTP": next to a numeric example that reads
  # as a one-time-password prompt, and password managers offer to fill a 2FA
  # code no matter what opt-outs the input carries.
  # With several fix commits (a fix plus its backports) no single one settles it:
  # which applies depends on the branch you track, so the reader is pointed at
  # the set rather than told one sha means safety.
  defp checker_placeholder(%{"otp_release?" => true}), do: "Erlang release, e.g. 26.2.5.6"

  defp checker_placeholder(%{"otp_package?" => true} = package),
    do: "#{package["bare_name"]} application version, e.g. #{sample_version(package)}"

  defp checker_placeholder(package), do: "#{package["bare_name"]} version, e.g. #{sample_version(package)}"

  # The verdict line: plain text (a sentence), never a pill. Colour follows the
  # record's own answer - error for affected, success for unaffected - and an
  # input we could not place NEVER gets a coloured verdict.
  defp verdict(%{verdict: nil} = assigns) do
    ~H"""
    <span class="text-sm text-base-content/40">
      type your {@package["bare_name"]} version to check
    </span>
    """
  end

  defp verdict(%{verdict: {:error, :unparseable}} = assigns) do
    ~H"""
    <span class="text-sm text-base-content/40">not a recognizable version</span>
    """
  end

  # R releases (R16B03 and earlier) are outside what this record covers: the
  # derivation orders numeric releases only, so it has nothing to say about
  # them either way. Warning-toned like `unknown`, never green.
  defp verdict(%{verdict: {:error, :r_series}} = assigns) do
    ~H"""
    <span class="text-sm">
      <b class="font-bold text-warning">? R releases aren't supported</b>
      <span class="text-base-content/60">
        — this record doesn't say whether R16B03 and earlier are affected
      </span>
    </span>
    """
  end

  defp verdict(%{verdict: {:ok, :affected}} = assigns) do
    assigns = assign(assigns, :subject, verdict_subject(assigns.package, assigns.input))

    ~H"""
    <span class="text-sm">
      <b class="font-bold text-error">✗ {@subject} is affected</b>
    </span>
    """
  end

  defp verdict(%{verdict: {:ok, :unaffected}} = assigns) do
    assigns = assign(assigns, :subject, verdict_subject(assigns.package, assigns.input))

    ~H"""
    <span class="text-sm">
      <b class="font-bold text-success">✓ {@subject} is not affected</b>
    </span>
    """
  end

  # The record genuinely does not say - either the range covering this version
  # is marked `unknown`, or nothing covers it and the product's own
  # `defaultStatus` is `unknown`. Neither red nor green: claiming either way
  # would be a guess, and "unknown" is not "safe".
  defp verdict(%{verdict: {:ok, :unknown}} = assigns) do
    assigns = assign(assigns, :subject, verdict_subject(assigns.package, assigns.input))

    ~H"""
    <span class="text-sm">
      <b class="font-bold text-warning">? {@subject}</b>
      <span class="text-base-content/60">
        — this record doesn't say whether this version is affected
      </span>
    </span>
    """
  end

  # A product we could not order at all never reaches the input, so this is the
  # residual case: an entry that declares a scheme it doesn't keep to.
  defp verdict(%{verdict: {:error, :unsupported}} = assigns) do
    ~H"""
    <span class="text-sm text-base-content/40">
      this record's versions can't be compared automatically
    </span>
    """
  end

  # The verdict subject: release checkers read "<app> in Erlang <release>";
  # everything else reads "<name> <version>". App-version-fallback packages
  # read "<name> <version> (Erlang application)" (component appended by the
  # callers below).
  defp verdict_subject(%{"otp_release?" => true} = package, input) do
    "#{package["bare_name"]} in #{otp_release_label(input)}"
  end

  defp verdict_subject(%{"otp_package?" => true} = package, input) do
    "#{package["bare_name"]} #{input} (Erlang application)"
  end

  defp verdict_subject(package, input), do: "#{package["bare_name"]} #{input}"

  # A visitor may still TYPE "OTP-26.2.5.6" — the release's real tag, and
  # what upstream advisories print — so it's accepted, not reflected back.
  defp otp_release_label("OTP-" <> rest), do: "Erlang #{rest}"
  defp otp_release_label(input), do: "Erlang #{input}"

  # Skips the "0"/"" zero-sentinel (an absent real lower bound, same
  # convention as `VarselWeb.CveHTML.zero_lower?/1`) — a placeholder reading
  # "e.g. 0" is nonsense, so the first range with a REAL version wins, or the
  # generic example when every range's lower bound is a sentinel.
  defp sample_version(%{"versions" => versions}) do
    versions
    |> Enum.filter(&(&1["status"] == "affected"))
    |> Enum.find_value(&real_version/1)
    |> case do
      nil -> "1.2.3"
      version -> version
    end
  end

  defp sample_version(_package), do: "1.2.3"

  defp real_version(%{"version" => version}) when version not in [nil, "", "0"], do: version
  defp real_version(_range), do: nil
end
