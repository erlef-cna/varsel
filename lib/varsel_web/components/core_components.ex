# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CoreComponents do
  @moduledoc """
  Provides core UI components.

  At first glance, this module may seem daunting, but its goal is to provide
  core building blocks for your application, such as tables, forms, and
  inputs. The components consist mostly of markup and are well-documented
  with doc strings and declarative assigns. You may customize and style
  them in any way you want, based on your application growth and needs.

  The foundation for styling is Tailwind CSS, a utility-first CSS framework,
  augmented with daisyUI, a Tailwind CSS plugin that provides UI components
  and themes. Here are useful references:

    * [daisyUI](https://daisyui.com/docs/intro/) - a good place to get
      started and see the available components.

    * [Tailwind CSS](https://tailwindcss.com) - the foundational framework
      we build on. You will use it for layout, sizing, flexbox, grid, and
      spacing.

    * [Heroicons](https://heroicons.com) - see `icon/1` for usage.

    * [Phoenix.Component](https://hexdocs.pm/phoenix_live_view/Phoenix.Component.html) -
      the component system used by Phoenix. Some components, such as `<.link>`
      and `<.form>`, are defined there.

  """
  use Phoenix.Component
  use Gettext, backend: VarselWeb.Gettext

  alias AshPhoenix.LiveView, as: AshLiveView
  alias Phoenix.HTML.Form
  alias Phoenix.HTML.FormField
  alias Phoenix.LiveView.JS

  @doc """
  Renders flash notices.

  ## Examples

      <.flash kind={:info} flash={@flash} />
      <.flash kind={:info} phx-mounted={show("#flash")}>Welcome Back!</.flash>
  """
  attr :id, :string, doc: "the optional id of flash container"
  attr :flash, :map, default: %{}, doc: "the map of flash messages to display"
  attr :title, :string, default: nil
  attr :kind, :atom, values: [:info, :error], doc: "used for styling and flash lookup"
  attr :rest, :global, doc: "the arbitrary HTML attributes to add to the flash container"

  slot :inner_block, doc: "the optional inner block that renders the flash message"

  def flash(assigns) do
    assigns = assign_new(assigns, :id, fn -> "flash-#{assigns.kind}" end)

    ~H"""
    <div
      :if={msg = render_slot(@inner_block) || Phoenix.Flash.get(@flash, @kind)}
      id={@id}
      phx-click={JS.push("lv:clear-flash", value: %{key: @kind}) |> hide("##{@id}")}
      role="alert"
      class="toast toast-top toast-end z-50"
      {@rest}
    >
      <div class={[
        "alert w-80 sm:w-96 max-w-80 sm:max-w-96 text-wrap",
        @kind == :info && "alert-info",
        @kind == :error && "alert-error"
      ]}>
        <.icon :if={@kind == :info} name="hero-information-circle" class="size-5 shrink-0" />
        <.icon :if={@kind == :error} name="hero-exclamation-circle" class="size-5 shrink-0" />
        <div>
          <p :if={@title} class="font-semibold">{@title}</p>
          <p>{msg}</p>
        </div>
        <div class="flex-1" />
        <button type="button" class="group self-start cursor-pointer" aria-label={gettext("close")}>
          <.icon name="hero-x-mark" class="size-5 opacity-40 group-hover:opacity-70" />
        </button>
      </div>
    </div>
    """
  end

  @doc """
  Renders a button with navigation support.

  ## Examples

      <.button>Send!</.button>
      <.button phx-click="go" variant="primary">Send!</.button>
      <.button navigate={~p"/"}>Home</.button>
  """
  attr :rest, :global, include: ~w(href navigate patch method download name value disabled)
  attr :class, :any
  attr :variant, :string, values: ~w(primary)
  slot :inner_block, required: true

  def button(%{rest: rest} = assigns) do
    variants = %{"primary" => "btn-primary", nil => "btn-primary btn-soft"}

    assigns =
      assign_new(assigns, :class, fn ->
        ["btn", Map.fetch!(variants, assigns[:variant])]
      end)

    if rest[:href] || rest[:navigate] || rest[:patch] do
      ~H"""
      <.link class={@class} {@rest}>
        {render_slot(@inner_block)}
      </.link>
      """
    else
      ~H"""
      <button class={@class} {@rest}>
        {render_slot(@inner_block)}
      </button>
      """
    end
  end

  @doc """
  Renders the full-width console page header: a tinted band under the navbar
  with eyebrow, title and subtitle on the left and the page's actions on the
  right. Content below it lays out its own container.
  """
  attr :title, :string, required: true
  attr :subtitle, :string, default: nil
  attr :eyebrow, :string, default: "CNA Console"
  slot :actions

  def console_header(assigns) do
    ~H"""
    <div class="console-band">
      <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-6 flex flex-wrap items-end justify-between gap-x-8 gap-y-4">
        <div>
          <p class="eef-eyebrow mb-1">{@eyebrow}</p>
          <h1 class="text-2xl font-bold leading-tight">{@title}</h1>
          <p :if={@subtitle} class="text-sm text-base-content/60 mt-0.5">{@subtitle}</p>
        </div>
        <div :if={@actions != []} class="flex flex-wrap items-center gap-2 pb-0.5">
          {render_slot(@actions)}
        </div>
      </div>
    </div>
    """
  end

  @doc """
  Renders the console's stat-tile row: one clickable tile per queue state,
  count on top, dot + label below — the overview and the filter are the same
  control. Clicking pushes `event` with the tile's value as the `filter`
  param. Options are maps with `:value`, `:label`, `:count` and an optional
  `:dot` (a background color class).
  """
  attr :active, :string, required: true
  attr :event, :string, default: "filter"
  attr :options, :list, required: true

  def stat_tiles(assigns) do
    ~H"""
    <div class="grid grid-cols-[repeat(auto-fit,minmax(8rem,1fr))] gap-2">
      <button
        :for={option <- @options}
        type="button"
        class={[
          "rounded-lg border p-3 text-left transition-colors cursor-pointer",
          if(@active == option.value,
            do: "border-primary bg-primary/10",
            else: "border-base-300 bg-base-200 hover:bg-base-300/60"
          )
        ]}
        phx-click={@event}
        phx-value-filter={option.value}
      >
        <div class="text-2xl font-bold leading-tight tabular-nums">{option.count}</div>
        <div class={[
          "flex items-center gap-1.5 mt-0.5 text-[0.68rem] font-semibold uppercase tracking-wider",
          if(@active == option.value, do: "text-primary", else: "text-base-content/60")
        ]}>
          <span :if={option[:dot]} class={["size-1.5 rounded-full shrink-0", option.dot]}></span>
          <span class="truncate">{option.label}</span>
        </div>
      </button>
    </div>
    """
  end

  @doc """
  Renders a console panel: a bordered card with a small-caps title row and
  optional actions on its right. The workspace rails and cards are built
  from these. `editing?` shifts the border to a primary tint — the "you are
  editing this card" signal used while a section's editor is open in place.
  """
  attr :id, :string, default: nil
  attr :title, :string, required: true
  attr :class, :any, default: nil
  attr :editing?, :boolean, default: false
  slot :actions
  slot :inner_block, required: true

  def panel(assigns) do
    ~H"""
    <section
      id={@id}
      class={[
        "rounded-box border bg-base-200 p-4",
        if(@editing?, do: "border-primary/50", else: "border-base-300"),
        @class
      ]}
    >
      <h3 class="flex items-center gap-3 text-[0.68rem] font-bold uppercase tracking-wider text-base-content/60 mb-2.5">
        {@title}
        <span
          :if={@actions != []}
          class="ml-auto flex items-center gap-3 normal-case tracking-normal font-semibold text-xs"
        >
          {render_slot(@actions)}
        </span>
      </h3>
      {render_slot(@inner_block)}
    </section>
    """
  end

  @doc """
  Renders read-only source code with Lumis syntax highlighting inside the
  standard codebox treatment. The generated `assets/vendor/css/lumis.css`
  (see `mix generate_lumis_css`) owns the box — border, base-100 background,
  radius, padding, horizontal scrolling — and the token colors for both site
  themes; `class` is for placement extras (margins, max-height). Display
  only: editable JSON stays in raw textareas.
  """
  attr :source, :string, required: true
  attr :language, :string, default: "json"
  attr :class, :any, default: nil

  def code_block(assigns) do
    ~H"""
    {Phoenix.HTML.raw(
      Lumis.highlight!(@source,
        formatter: {:html_linked, language: @language, pre_class: code_block_class(@class)}
      )
    )}
    """
  end

  defp code_block_class(class) do
    ["text-xs leading-5", class]
    |> List.flatten()
    |> Enum.filter(&is_binary/1)
    |> Enum.join(" ")
  end

  @doc """
  Renders a lifecycle state as dot + word — color never carries the meaning
  alone. `dot` is a background color class (e.g. "bg-warning").
  """
  attr :dot, :string, required: true
  attr :class, :any, default: nil
  slot :inner_block, required: true

  def state(assigns) do
    ~H"""
    <span class={["inline-flex items-center gap-1.5 whitespace-nowrap", @class]}>
      <span class={["size-1.5 rounded-full shrink-0", @dot]}></span>
      {render_slot(@inner_block)}
    </span>
    """
  end

  @doc """
  Renders a CVSS severity chip: rating word/initial + score in one chip,
  bucketed from `score` alone (none = exactly 0.0, low 0.1–3.9, medium
  4.0–6.9, high 7.0–8.9, critical 9.0–10.0 — the same thresholds
  `:cvss.rating/1` uses). Colored text on a tinted background for every
  bucket except critical, which is the sole FILLED chip (`--sev-critical-*`
  tokens) so the ranking survives color-blindness.

  `score: nil` renders the dashed "no score" chip instead — an unscored case
  is distinct from a real 0.0 (the grey NONE chip). `variant: :compact`
  (default) renders the initial ("C 9.1"); `:full` renders the word
  ("CRITICAL 9.1").
  """
  attr :score, :float, default: nil
  attr :variant, :atom, default: :compact, values: [:compact, :full]
  attr :class, :any, default: nil

  def severity_chip(%{score: nil} = assigns) do
    ~H"""
    <span class={[
      "inline-flex items-center rounded-[5px] border border-dashed border-base-content/25 px-[0.42rem] py-[0.07rem]",
      "text-[0.67rem] font-semibold whitespace-nowrap text-base-content/50",
      @class
    ]}>
      no score
    </span>
    """
  end

  def severity_chip(assigns) do
    bucket = severity_bucket(assigns.score)
    assigns = assign(assigns, bucket: bucket, label: severity_label(bucket, assigns.variant))

    ~H"""
    <span class={[
      "inline-flex items-center gap-[0.35ch] rounded-[5px] px-[0.42rem] py-[0.09rem]",
      "text-[0.67rem] font-bold tabular-nums whitespace-nowrap",
      severity_chip_class(@bucket),
      @class
    ]}>
      {@label} {format_severity_score(@score)}
    </span>
    """
  end

  @doc """
  Buckets a CVSS score into a severity rating atom. `nil` is not a valid
  input here — callers rendering an unscored case use `severity_chip`'s
  `score: nil` path instead, which is a distinct "no score" state, not NONE.
  """
  @spec severity_bucket(float()) :: :none | :low | :medium | :high | :critical
  def severity_bucket(+0.0), do: :none
  def severity_bucket(score) when score >= 0.1 and score <= 3.9, do: :low
  def severity_bucket(score) when score >= 4.0 and score <= 6.9, do: :medium
  def severity_bucket(score) when score >= 7.0 and score <= 8.9, do: :high
  def severity_bucket(score) when score >= 9.0 and score <= 10.0, do: :critical

  defp severity_label(bucket, :compact), do: bucket |> to_string() |> String.first() |> String.upcase()

  defp severity_label(bucket, :full), do: bucket |> to_string() |> String.upcase()

  defp severity_chip_class(:critical),
    do:
      "text-[color:var(--sev-critical-text)] bg-[color:var(--sev-critical-fill)] border border-[color:var(--sev-critical-line)]"

  defp severity_chip_class(:high), do: "text-[color:var(--sev-high)] bg-[color:var(--sev-high-tint)]"

  defp severity_chip_class(:medium), do: "text-[color:var(--sev-medium)] bg-[color:var(--sev-medium-tint)]"

  defp severity_chip_class(:low), do: "text-[color:var(--sev-low)] bg-[color:var(--sev-low-tint)]"

  defp severity_chip_class(:none), do: "text-[color:var(--sev-none)] bg-[color:var(--sev-none-tint)]"

  defp format_severity_score(score), do: :erlang.float_to_binary(score / 1, decimals: 1)

  @doc """
  Renders prev/next pagination for an `Ash.Page.Offset` (loaded with a
  count). Clicking pushes `event` with "prev"/"next" as the `page` param —
  feed that to `VarselWeb.LivePagination.change_page/3`. Renders nothing for
  a single page.
  """
  attr :page, :any, required: true, doc: "an Ash.Page.Offset with count loaded"
  attr :event, :string, default: "paginate"

  def pagination(assigns) do
    assigns =
      assign(assigns,
        # AshPhoenix's page_number/1 is zero-based for exact-multiple offsets.
        page_number: div(assigns.page.offset || 0, max(assigns.page.limit, 1)) + 1,
        last_page: AshLiveView.last_page(assigns.page)
      )

    ~H"""
    <div :if={is_integer(@last_page) and @last_page > 1} class="flex items-center gap-1">
      <button
        type="button"
        class="btn btn-ghost btn-xs border border-base-300"
        disabled={not AshLiveView.prev_page?(@page)}
        phx-click={@event}
        phx-value-page="prev"
      >
        «
      </button>
      <span class="text-xs text-base-content/60 tabular-nums px-2">
        Page {@page_number} of {@last_page}
      </span>
      <button
        type="button"
        class="btn btn-ghost btn-xs border border-base-300"
        disabled={not AshLiveView.next_page?(@page)}
        phx-click={@event}
        phx-value-page="next"
      >
        »
      </button>
    </div>
    """
  end

  @doc """
  Renders a table card's footer pager row: "N per page · M total" on the
  left, prev/jump-to-page/next on the right. The page number is a numeric
  input — typing a value and pressing Enter pushes `jump_event` with that
  value as the `page` param (feed it to
  `VarselWeb.LivePagination.jump_to_page/3`); prev/next push `page_event`
  same as `pagination/1`. Renders nothing at zero results (callers show an
  empty-state message instead).
  """
  attr :page, :any, required: true, doc: "an Ash.Page.Offset with count loaded"
  attr :page_event, :string, default: "paginate"
  attr :jump_event, :string, default: "jump_page"
  attr :noun, :string, default: "case", doc: "singular; pluralized with a trailing \"s\""

  def jump_pagination(assigns) do
    assigns =
      assign(assigns,
        page_number: div(assigns.page.offset || 0, max(assigns.page.limit, 1)) + 1,
        last_page: AshLiveView.last_page(assigns.page)
      )

    ~H"""
    <div
      :if={is_integer(@page.count) and @page.count > 0}
      class="flex flex-wrap items-center justify-between gap-3 px-3.5 py-2 border-t border-base-300 text-xs text-base-content/60"
    >
      <span>
        {@page.limit} per page · {@page.count} {if @page.count == 1, do: @noun, else: @noun <> "s"}
      </span>
      <%!-- The form wraps the whole pager cluster: a <form> inside a <span>
            is invalid flow-in-phrasing markup that browsers may re-parent,
            detaching the submit binding. The prev/next buttons are
            type="button" so only Enter in the input submits. --%>
      <form phx-submit={@jump_event} class="inline-flex items-center gap-2">
        <button
          type="button"
          class={["px-1.5 rounded border", pbtn_class(AshLiveView.prev_page?(@page))]}
          disabled={not AshLiveView.prev_page?(@page)}
          phx-click={@page_event}
          phx-value-page="prev"
        >
          «
        </button>
        Page
        <input
          type="text"
          inputmode="numeric"
          name="page"
          value={@page_number}
          class="w-9 text-center font-mono bg-base-100 border border-base-300 rounded px-1 py-0.5"
        /> of {@last_page}
        <button
          type="button"
          class={["px-1.5 rounded border", pbtn_class(AshLiveView.next_page?(@page))]}
          disabled={not AshLiveView.next_page?(@page)}
          phx-click={@page_event}
          phx-value-page="next"
        >
          »
        </button>
      </form>
    </div>
    """
  end

  defp pbtn_class(true), do: "border-base-300"
  defp pbtn_class(false), do: "border-base-300/50 text-base-content/40"

  @doc """
  Renders the console list card's search input: a magnifier icon inside a
  rounded field. Wrap it in the page's own `phx-change` form — the input's
  name is `query`.
  """
  attr :value, :string, required: true
  attr :placeholder, :string, required: true

  def console_search(assigns) do
    ~H"""
    <label class="input input-sm flex items-center gap-2 w-64 rounded-lg">
      <.icon name="hero-magnifying-glass-mini" class="size-4 text-base-content/40 shrink-0" />
      <input
        type="search"
        name="query"
        value={@value}
        placeholder={@placeholder}
        autocomplete="off"
        phx-debounce="200"
        class="grow min-w-0 bg-transparent focus:outline-none"
      />
    </label>
    """
  end

  @doc """
  Renders an input with label and error messages.

  A `Phoenix.HTML.FormField` may be passed as argument,
  which is used to retrieve the input name, id, and values.
  Otherwise all attributes may be passed explicitly.

  ## Types

  This function accepts all HTML input types, considering that:

    * You may also set `type="select"` to render a `<select>` tag

    * `type="checkbox"` is used exclusively to render boolean values

    * For live file uploads, see `Phoenix.Component.live_file_input/1`

  See https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input
  for more information. Unsupported types, such as radio, are best
  written directly in your templates.

  ## Examples

  ```heex
  <.input field={@form[:email]} type="email" />
  <.input name="my-input" errors={["oh no!"]} />
  ```

  ## Select type

  When using `type="select"`, you must pass the `options` and optionally
  a `value` to mark which option should be preselected.

  ```heex
  <.input field={@form[:user_type]} type="select" options={["Admin": "admin", "User": "user"]} />
  ```

  For more information on what kind of data can be passed to `options` see
  [`options_for_select`](https://hexdocs.pm/phoenix_html/Phoenix.HTML.Form.html#options_for_select/2).
  """
  attr :id, :any, default: nil
  attr :name, :any
  attr :value, :any

  attr :type, :string,
    default: "text",
    values: ~w(checkbox color date datetime-local email file month number password
               search select tel text textarea time url week hidden)

  attr :field, FormField, doc: "a form field struct retrieved from the form, for example: @form[:email]"

  attr :errors, :list, default: []
  attr :checked, :boolean, doc: "the checked flag for checkbox inputs"
  attr :prompt, :string, default: nil, doc: "the prompt for select inputs"
  attr :options, :list, doc: "the options to pass to Phoenix.HTML.Form.options_for_select/2"
  attr :multiple, :boolean, default: false, doc: "the multiple flag for select inputs"
  attr :class, :any, default: nil, doc: "the input class to use over defaults"
  attr :error_class, :any, default: nil, doc: "the input error class to use over defaults"

  attr :rest, :global, include: ~w(accept autocomplete capture cols disabled form list max maxlength min minlength
                multiple pattern placeholder readonly required rows size step)

  slot :label, doc: "the field label; may contain rich content such as links"
  slot :description, doc: "optional helper text rendered small and muted below the input"

  def input(%{field: %FormField{} = field} = assigns) do
    errors = if Phoenix.Component.used_input?(field), do: field.errors, else: []

    assigns
    |> assign(field: nil, id: assigns.id || field.id)
    |> assign(:errors, Enum.map(errors, &translate_error(&1)))
    |> assign_new(:name, fn -> if assigns.multiple, do: field.name <> "[]", else: field.name end)
    |> assign_new(:value, fn -> field.value end)
    |> input()
  end

  def input(%{type: "hidden"} = assigns) do
    ~H"""
    <input type="hidden" id={@id} name={@name} value={@value} {@rest} />
    """
  end

  def input(%{type: "checkbox"} = assigns) do
    assigns =
      assign_new(assigns, :checked, fn ->
        Form.normalize_value("checkbox", assigns[:value])
      end)

    ~H"""
    <div class="fieldset mb-2">
      <label for={@id} class="flex items-center gap-2">
        <input
          type="hidden"
          name={@name}
          value="false"
          disabled={@rest[:disabled]}
          form={@rest[:form]}
        />
        <input
          type="checkbox"
          id={@id}
          name={@name}
          value="true"
          checked={@checked}
          class={@class || "checkbox checkbox-sm"}
          {@rest}
        />
        <span :if={@label != []}>{render_slot(@label)}</span>
      </label>
      <.description description={@description} />
      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end

  def input(%{type: "select"} = assigns) do
    ~H"""
    <div class="fieldset mb-2">
      <label for={@id}>
        <span :if={@label != []} class="label mb-1">{render_slot(@label)}</span>
        <select
          id={@id}
          name={@name}
          class={[@class || "w-full select", @errors != [] && (@error_class || "select-error")]}
          multiple={@multiple}
          {@rest}
        >
          <option :if={@prompt} value="">{@prompt}</option>
          {Phoenix.HTML.Form.options_for_select(@options, @value)}
        </select>
      </label>
      <.description description={@description} />
      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end

  def input(%{type: "textarea"} = assigns) do
    ~H"""
    <div class="fieldset mb-2">
      <label for={@id}>
        <span :if={@label != []} class="label mb-1">{render_slot(@label)}</span>
        <textarea
          id={@id}
          name={@name}
          class={[
            @class || "w-full textarea",
            @errors != [] && (@error_class || "textarea-error")
          ]}
          {@rest}
        >{Phoenix.HTML.Form.normalize_value("textarea", @value)}</textarea>
      </label>
      <.description description={@description} />
      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end

  # All other inputs text, datetime-local, url, password, etc. are handled here...
  def input(assigns) do
    ~H"""
    <div class="fieldset mb-2">
      <label for={@id}>
        <span :if={@label != []} class="label mb-1">{render_slot(@label)}</span>
        <input
          type={@type}
          name={@name}
          id={@id}
          value={Phoenix.HTML.Form.normalize_value(@type, @value)}
          class={[
            @class || "w-full input",
            @errors != [] && (@error_class || "input-error")
          ]}
          {@rest}
        />
      </label>
      <.description description={@description} />
      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end

  defp description(assigns) do
    ~H"""
    <p :if={@description != []} class="mt-1 text-xs text-base-content/60">
      {render_slot(@description)}
    </p>
    """
  end

  # Helper used by inputs to generate form errors
  defp error(assigns) do
    ~H"""
    <p class="mt-1.5 flex gap-2 items-center text-sm text-error">
      <.icon name="hero-exclamation-circle" class="size-5" />
      {render_slot(@inner_block)}
    </p>
    """
  end

  @doc """
  Renders a header with title.
  """
  attr :class, :string, default: nil
  attr :rest, :global
  slot :inner_block, required: true
  slot :subtitle
  slot :actions

  def header(assigns) do
    ~H"""
    <header
      class={[@actions != [] && "flex items-center justify-between gap-6", "pb-4", @class]}
      {@rest}
    >
      <div>
        <h1 class="text-lg font-semibold leading-8">
          {render_slot(@inner_block)}
        </h1>
        <p :if={@subtitle != []} class="text-sm text-base-content/70">
          {render_slot(@subtitle)}
        </p>
      </div>
      <div class="flex-none">{render_slot(@actions)}</div>
    </header>
    """
  end

  @doc """
  Renders a table with generic styling.

  ## Examples

      <.table id="users" rows={@users}>
        <:col :let={user} label="id">{user.id}</:col>
        <:col :let={user} label="username">{user.username}</:col>
      </.table>
  """
  attr :id, :string, required: true
  attr :rows, :list, required: true
  attr :row_id, :any, default: nil, doc: "the function for generating the row id"
  attr :row_click, :any, default: nil, doc: "the function for handling phx-click on each row"

  attr :row_item, :any,
    default: &Function.identity/1,
    doc: "the function for mapping each row before calling the :col and :action slots"

  slot :col, required: true do
    attr :label, :string
  end

  slot :action, doc: "the slot for showing user actions in the last table column"

  def table(assigns) do
    assigns =
      with %{rows: %Phoenix.LiveView.LiveStream{}} <- assigns do
        assign(assigns, row_id: assigns.row_id || fn {id, _item} -> id end)
      end

    ~H"""
    <table class="table table-zebra">
      <thead>
        <tr>
          <th :for={col <- @col}>{col[:label]}</th>
          <th :if={@action != []}>
            <span class="sr-only">{gettext("Actions")}</span>
          </th>
        </tr>
      </thead>
      <tbody id={@id} phx-update={is_struct(@rows, Phoenix.LiveView.LiveStream) && "stream"}>
        <tr :for={row <- @rows} id={@row_id && @row_id.(row)}>
          <td
            :for={col <- @col}
            phx-click={@row_click && @row_click.(row)}
            class={@row_click && "hover:cursor-pointer"}
          >
            {render_slot(col, @row_item.(row))}
          </td>
          <td :if={@action != []} class="w-0 font-semibold">
            <div class="flex gap-4">
              <%= for action <- @action do %>
                {render_slot(action, @row_item.(row))}
              <% end %>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    """
  end

  @doc """
  Renders a data list.

  ## Examples

      <.list>
        <:item title="Title">{@post.title}</:item>
        <:item title="Views">{@post.views}</:item>
      </.list>
  """
  slot :item, required: true do
    attr :title, :string, required: true
  end

  def list(assigns) do
    ~H"""
    <ul class="list">
      <li :for={item <- @item} class="list-row">
        <div class="list-col-grow">
          <div class="font-bold">{item.title}</div>
          <div>{render_slot(item)}</div>
        </div>
      </li>
    </ul>
    """
  end

  @doc """
  Renders a [Heroicon](https://heroicons.com).

  Heroicons come in three styles – outline, solid, and mini.
  By default, the outline style is used, but solid and mini may
  be applied by using the `-solid` and `-mini` suffix.

  You can customize the size and colors of the icons by setting
  width, height, and background color classes.

  Icons are extracted from the `deps/heroicons` directory and bundled within
  your compiled app.css by the plugin in `assets/vendor/heroicons.js`.

  ## Examples

      <.icon name="hero-x-mark" />
      <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
  """
  attr :name, :string, required: true
  attr :class, :any, default: "size-4"

  def icon(%{name: "hero-" <> _} = assigns) do
    ~H"""
    <span class={[@name, @class]} />
    """
  end

  ## JS Commands

  def show(js \\ %JS{}, selector) do
    JS.show(js,
      to: selector,
      time: 300,
      transition:
        {"transition-all ease-out duration-300", "opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95",
         "opacity-100 translate-y-0 sm:scale-100"}
    )
  end

  def hide(js \\ %JS{}, selector) do
    JS.hide(js,
      to: selector,
      time: 200,
      transition:
        {"transition-all ease-in duration-200", "opacity-100 translate-y-0 sm:scale-100",
         "opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"}
    )
  end

  @doc """
  Translates an error message using gettext.
  """
  def translate_error({msg, opts}) do
    # When using gettext, we typically pass the strings we want
    # to translate as a static argument:
    #
    #     # Translate the number of files with plural rules
    #     dngettext("errors", "1 file", "%{count} files", count)
    #
    # However the error messages in our forms and APIs are generated
    # dynamically, so we need to translate them by calling Gettext
    # with our gettext backend as first argument. Translations are
    # available in the errors.po file (as we use the "errors" domain).
    if count = opts[:count] do
      Gettext.dngettext(VarselWeb.Gettext, "errors", msg, msg, count, opts)
    else
      Gettext.dgettext(VarselWeb.Gettext, "errors", msg, opts)
    end
  end

  @doc """
  Translates the errors for a field from a keyword list of errors.
  """
  def translate_errors(errors, field) when is_list(errors) do
    for {^field, {msg, opts}} <- errors, do: translate_error({msg, opts})
  end
end
