# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CvssInput do
  @moduledoc """
  CVSS v4.0 form field with a small calculator: one toggle group per base
  metric, the resulting base score, and the severity rating — scored live by
  the same `:cvss` library that expands the vector into the published record.

  The vector text input stays the source of truth (pasting a full vector
  still works and updates the toggles); toggles rewrite the vector while
  preserving any non-base metrics (threat/environmental/supplemental) a
  pasted vector carries. Toggling an empty field starts from the all-benign
  baseline (score 0.0) and applies the clicked selection.

      <.live_component
        module={VarselWeb.CvssInput}
        id="case-cvss"
        field={@form[:cvss_v4]}
        label="CVSS v4.0"
      />
  """
  use VarselWeb, :live_component

  alias Varsel.Types.CVSS

  @prefix "CVSS:4.0"

  # The eleven v4.0 base metrics, in specification order.
  @metrics [
    {"AV", "Attack Vector", [{"N", "Network"}, {"A", "Adjacent"}, {"L", "Local"}, {"P", "Physical"}]},
    {"AC", "Attack Complexity", [{"L", "Low"}, {"H", "High"}]},
    {"AT", "Attack Requirements", [{"N", "None"}, {"P", "Present"}]},
    {"PR", "Privileges Required", [{"N", "None"}, {"L", "Low"}, {"H", "High"}]},
    {"UI", "User Interaction", [{"N", "None"}, {"P", "Passive"}, {"A", "Active"}]},
    {"VC", "Confidentiality (Vulnerable System)", [{"H", "High"}, {"L", "Low"}, {"N", "None"}]},
    {"VI", "Integrity (Vulnerable System)", [{"H", "High"}, {"L", "Low"}, {"N", "None"}]},
    {"VA", "Availability (Vulnerable System)", [{"H", "High"}, {"L", "Low"}, {"N", "None"}]},
    {"SC", "Confidentiality (Subsequent System)", [{"H", "High"}, {"L", "Low"}, {"N", "None"}]},
    {"SI", "Integrity (Subsequent System)", [{"H", "High"}, {"L", "Low"}, {"N", "None"}]},
    {"SA", "Availability (Subsequent System)", [{"H", "High"}, {"L", "Low"}, {"N", "None"}]}
  ]

  @base_codes Enum.map(@metrics, &elem(&1, 0))

  # All-benign baseline a first toggle starts from (base score 0.0).
  @baseline Enum.map(@base_codes, fn
              "AC" -> {"AC", "L"}
              code -> {code, "N"}
            end)

  @impl Phoenix.LiveComponent
  def update(assigns, socket) do
    socket =
      socket
      |> assign(assigns)
      |> assign_new(:label, fn -> "CVSS v4.0" end)
      |> assign_new(:vector, fn -> nil end)
      |> assign_new(:last_written, fn -> nil end)

    incoming = form_value(socket.assigns.field)

    # Adopt the form's value unless it is what we last wrote ourselves (a
    # parent re-render must not clobber toggle edits that the form has not
    # validated yet).
    socket =
      if socket.assigns[:vector] == incoming or socket.assigns[:last_written] == incoming do
        socket
      else
        assign(socket, vector: incoming, last_written: nil)
      end

    {:ok, assign_scored(socket)}
  end

  @impl Phoenix.LiveComponent
  # The param is deliberately NOT named "value": browsers merge the clicked
  # button's own DOM value ("" for plain <button>s) into the click payload
  # under "value", clobbering a phx-value-value attribute.
  def handle_event("metric", %{"code" => code, "selection" => value}, socket) when code in @base_codes do
    vector =
      socket.assigns.vector
      |> parse_pairs()
      |> case do
        [] -> @baseline
        pairs -> pairs
      end
      |> put_metric(code, value)
      |> compose()

    {:noreply, assign_scored(assign(socket, vector: vector, last_written: vector))}
  end

  def handle_event("vector_changed", %{"value" => value}, socket) do
    {:noreply, assign_scored(assign(socket, vector: value, last_written: value))}
  end

  @impl Phoenix.LiveComponent
  def render(assigns) do
    ~H"""
    <div id={@id} class="mb-2">
      <div class="flex items-center justify-between mb-1">
        <label class="label text-sm" for={@field.id}>{@label}</label>
        <div class="flex items-center gap-2">
          <.severity_chip :if={@score} score={@score} variant={:full} />
          <span :if={@vector not in [nil, ""] and is_nil(@score)} class="badge badge-sm badge-error">
            invalid vector
          </span>
        </div>
      </div>

      <input
        type="text"
        id={@field.id}
        name={@field.name}
        value={@vector}
        placeholder="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        class="w-full input font-mono text-sm"
        phx-keyup="vector_changed"
        phx-target={@myself}
        phx-debounce="300"
      />
      <p :for={error <- Enum.map(@field.errors, &translate_error/1)} class="text-error text-sm mt-1">
        {error}
      </p>

      <div class="grid sm:grid-cols-2 gap-x-6 gap-y-1 mt-2">
        <div :for={{code, name, options} <- metrics()} class="flex items-center justify-between gap-2">
          <span class="text-xs text-base-content/70">{name}</span>
          <div class="join">
            <button
              :for={{value, value_label} <- options}
              type="button"
              class={[
                "join-item btn btn-xs",
                if(selected(@vector, code) == value, do: "btn-primary", else: "btn-ghost")
              ]}
              title={"#{code}:#{value} — #{value_label}"}
              phx-click="metric"
              phx-value-code={code}
              phx-value-selection={value}
              phx-target={@myself}
            >
              {value_label}
            </button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  ## ------------------------------------------------------------- vector math

  defp metrics, do: @metrics

  defp form_value(field) do
    case field.value do
      %CVSS{vector: vector} -> vector
      value when is_binary(value) -> value
      _other -> nil
    end
  end

  defp assign_scored(socket) do
    case CVSS.cast_input(presence(socket.assigns.vector), version: [:v4]) do
      {:ok, %CVSS{} = cvss} -> assign(socket, score: cvss.score)
      _invalid_or_nil -> assign(socket, score: nil)
    end
  end

  defp parse_pairs(nil), do: []

  defp parse_pairs(vector) do
    vector
    |> String.replace_prefix(@prefix <> "/", "")
    |> String.split("/", trim: true)
    |> Enum.flat_map(fn part ->
      case String.split(part, ":", parts: 2) do
        # "CVSS" guards against a bare/leading version segment parsing as a metric.
        [code, value] when code != "CVSS" -> [{code, value}]
        _other -> []
      end
    end)
  end

  # Replaces (or appends, in spec order relative to the other base metrics)
  # one base metric; non-base metrics keep their position.
  defp put_metric(pairs, code, value) do
    if List.keymember?(pairs, code, 0) do
      List.keyreplace(pairs, code, 0, {code, value})
    else
      {base, extra} = Enum.split_with(pairs, fn {c, _} -> c in @base_codes end)

      base =
        Enum.sort_by([{code, value} | base], fn {c, _} ->
          Enum.find_index(@base_codes, &(&1 == c))
        end)

      base ++ extra
    end
  end

  defp compose(pairs) do
    Enum.map_join(
      [{"", @prefix} | Enum.map(pairs, fn {c, v} -> {c, "#{c}:#{v}"} end)],
      "/",
      &elem(&1, 1)
    )
  end

  defp selected(vector, code) do
    vector
    |> parse_pairs()
    |> List.keyfind(code, 0)
    |> then(fn
      {_code, value} -> value
      nil -> nil
    end)
  end

  defp presence(nil), do: nil
  defp presence(value), do: if(String.trim(value) == "", do: nil, else: value)
end
