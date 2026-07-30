# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AffectedCheckerLive do
  @moduledoc """
  The public CVE detail page's "Am I affected?" checker — a small LiveView
  mounted into the dead controller-rendered page (`cve_html/show.html.heex`)
  via `live_render/3`, since the page itself needs no other interactivity.
  Matching runs server-side (`VarselWeb.CveView.AffectedChecker`) against the
  SAME `versions[]` the page's Affected cards already render — no separate
  data source.

  Rev 3: the card ALWAYS renders for any record with an affected package —
  no exception clause. `VarselWeb.CveHTML.checker_packages/1` classifies
  every package into a `"state"` (`"checkable"`, `"all_affected"`,
  `"git_only"`, `"unorderable"`); only `"checkable"` gets a version input,
  the other three render a static/guidance body in its place. If NO
  affected package qualifies at all, the caller doesn't mount this LiveView
  — the "Am I affected?" card is absent from the page.

  ## Session payload

  `live_render/3`'s session must be JSON-safe, so the mount receives one map
  per package rather than the raw CNA `affected[]` structs — see
  `VarselWeb.CveHTML.checker_packages/1`'s doc for the full per-state shape.
  """
  use VarselWeb, :live_view

  alias VarselWeb.CveView.AffectedChecker

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

    verdict =
      if package["state"] == "checkable" do
        AffectedChecker.match(socket.assigns.input, package["versions"])
      end

    assign(socket, package: package, verdict: verdict)
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
          {pkg["purl"]}
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
            {pkg["purl"]}
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

  defp package_body(%{package: %{"state" => "checkable"}} = assigns) do
    ~H"""
    <div class="flex flex-wrap items-center gap-2.5">
      <%!-- Password managers read a lone text input in a <form> as a
            credential field and offer to fill it; each vendor needs its own
            opt-out — 1Password, LastPass, Bitwarden, Dashlane in order.
            Safari ignores all of them (and `autocomplete="url"`, tried and
            dropped) — its trigger is the wording, see `checker_placeholder/1`. --%>
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

  # Rev 3 addendum (i): defaultStatus:affected with no versions[] at all —
  # a static verdict, no input, red because it's the answer for everyone.
  defp package_body(%{package: %{"state" => "all_affected"}} = assigns) do
    ~H"""
    <div class="text-sm">
      <b class="font-bold text-error">✗ every version is affected</b>
      <span class="text-base-content/60">— no fixed release yet; watch References for a fix</span>
    </div>
    """
  end

  # Commit-only channel: no input (a disabled input is noise) — the fix
  # commit in mono, warn/ok-toned, plus how to use it.
  defp package_body(%{package: %{"state" => "git_only"}} = assigns) do
    ~H"""
    <div class="text-sm">
      <p class="mb-1.5">
        This record tracks affected code by commit, not by release — automatic version checking isn't available.
      </p>
      <p class="font-mono text-xs">
        <span :if={@package["intro_sha"]} class="text-base-content/60">introduced by </span>
        <code :if={@package["intro_sha"]} class="text-warning">{@package["intro_sha"]}</code>
        <span :if={@package["intro_sha"] && @package["fix_sha"]} class="text-base-content/60">
          ·
        </span>
        <span :if={@package["fix_sha"]} class="text-base-content/60">fixed by </span>
        <code :if={@package["fix_sha"]} class="text-success">{@package["fix_sha"]}</code>
      </p>
      <p :if={@package["fix_sha"]} class="mt-1.5 text-xs text-base-content/60">
        If your checkout includes <code>{@package["fix_sha"]}</code>
        you have the fix.
        <.link href="#affected" class="text-primary hover:underline">See the full range ↓</.link>
      </p>
    </div>
    """
  end

  # Rev 3 addendum (ii): vendor/product-only records with non-orderable
  # custom ranges — no input, the honest line, anchored down to the
  # Affected card's evidence.
  defp package_body(%{package: %{"state" => "unorderable"}} = assigns) do
    ~H"""
    <p class="text-sm">
      Version checking isn't available for this record — its versions can't be compared automatically.
      <.link href="#affected" class="text-primary hover:underline">See the affected ranges ↓</.link>
    </p>
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
  defp checker_placeholder(%{"otp_release?" => true}), do: "Erlang release, e.g. 26.2.5.6"

  defp checker_placeholder(%{"otp_package?" => true} = package),
    do: "#{package["bare_name"]} application version, e.g. #{sample_version(package)}"

  defp checker_placeholder(package), do: "#{package["bare_name"]} version, e.g. #{sample_version(package)}"

  # The verdict line: plain text (a sentence), never a pill. One token per
  # direction (--bad/error for unsafe, --ok/success for safe); unparseable
  # input NEVER gets a colored verdict.
  defp verdict(%{verdict: {:empty}} = assigns) do
    ~H"""
    <span class="text-sm text-base-content/40">
      type your {@package["bare_name"]} version to check
    </span>
    """
  end

  defp verdict(%{verdict: {:unparseable}} = assigns) do
    ~H"""
    <span class="text-sm text-base-content/40">not a recognizable version</span>
    """
  end

  # Verdict copy grammar (rev 3): single hit → own fix, no tail unless it's
  # on a non-latest branch; multi-branch → own fix leads, every OTHER
  # branch's fix follows "; also fixed in …", comma-listed, every fix
  # (including the leading one) labeled.
  defp verdict(%{verdict: {:affected, own_fix, other_fixes}} = assigns) do
    assigns =
      assign(assigns,
        subject: verdict_subject(assigns.package, assigns.input),
        own_fix: own_fix,
        other_fixes: other_fixes
      )

    ~H"""
    <span class="text-sm">
      <b class="font-bold text-error">✗ {@subject} is affected</b>
      <span :if={@own_fix || @other_fixes != []} class="text-base-content/60">
        — {affected_tail(@own_fix, @other_fixes)}
      </span>
    </span>
    """
  end

  defp verdict(%{verdict: {:fixed, via, latest}} = assigns) do
    assigns =
      assign(assigns,
        subject: verdict_subject(assigns.package, assigns.input),
        # "backported from" only when the matched fix is on a DIFFERENT
        # branch than the latest — never names the version the user typed.
        backport: latest && latest.raw != via.raw && latest
      )

    ~H"""
    <span class="text-sm">
      <b class="font-bold text-success">✓ {@subject} includes the fix</b>
      <span :if={@backport} class="text-base-content/60">
        — backported from {labelled_fix(@backport)}
      </span>
    </span>
    """
  end

  defp verdict(%{verdict: {:not_affected, intro}} = assigns) do
    assigns =
      assign(assigns,
        subject: verdict_subject(assigns.package, assigns.input),
        intro: intro && fix_version(intro)
      )

    ~H"""
    <span class="text-sm">
      <b class="font-bold text-success">✓ {@subject} is not affected</b>
      <span :if={@intro} class="text-base-content/60">
        — the flaw was introduced in {@intro}
      </span>
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

  # "fixed in <own>" leads; every OTHER branch's fix is comma-listed after
  # a single "; also fixed in " — every fix (including the leading one)
  # carries its branch label via `labelled_fix/1`.
  defp affected_tail(own_fix, other_fixes) do
    others = Enum.map(other_fixes, &labelled_fix/1)

    case {own_fix, others} do
      {nil, []} ->
        nil

      {nil, others} ->
        "fixed in " <> Enum.join(others, ", ")

      {own_fix, []} ->
        "fixed in #{labelled_fix(own_fix)}"

      {own_fix, others} ->
        "fixed in #{labelled_fix(own_fix)}; also fixed in " <> Enum.join(others, ", ")
    end
  end

  # `raw` is the record's own version string — literally "OTP-26.2.5.6" for
  # release-tagged records — so it's stripped here too; otherwise one verdict
  # mixes both vocabularies ("in Erlang 26.2.5.2 — fixed in OTP-26.2.5.6").
  defp labelled_fix(%{raw: raw, branch_label: nil}), do: fix_version(raw)
  defp labelled_fix(%{raw: raw, branch_label: label}), do: "#{fix_version(raw)} (#{label})"

  defp fix_version("OTP-" <> rest), do: rest
  defp fix_version(raw), do: raw

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
