# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequest.Checks.MayRunAction do
  @moduledoc """
  Whether the actor may run the action that a manual request stands in for,
  on the case or link it names. The question is the one the GitHub tab asks
  before it offers that action, so the answer is the same here and there.
  """

  use Ash.Policy.SimpleCheck

  alias Ash.Changeset
  alias Varsel.Cases

  @impl Ash.Policy.Check
  def describe(_opts), do: "actor may run the action the manual request stands in for"

  @impl Ash.Policy.SimpleCheck
  def match?(actor, %{subject: %Changeset{action: %{name: action}} = changeset}, _opts) do
    allowed?(action, actor, changeset)
  end

  def match?(_actor, _context, _opts), do: false

  defp allowed?(:prepare_link, actor, changeset) do
    with_case(actor, changeset, &Cases.can_edit_case?(actor, &1, %{}, validate?: true))
  end

  defp allowed?(:prepare_report, actor, changeset) do
    with_case(actor, changeset, &Cases.can_report_case_to_github?(actor, &1))
  end

  defp allowed?(:prepare_refresh, actor, changeset) do
    with_link(
      actor,
      changeset,
      &Cases.can_refresh_github_advisory_link?(actor, &1, %{}, validate?: true)
    )
  end

  defp allowed?(:prepare_pull, actor, changeset) do
    fields = Changeset.get_argument(changeset, :fields) || []

    with_link(
      actor,
      changeset,
      &Cases.can_pull_github_advisory?(actor, &1, fields, %{}, validate?: true)
    )
  end

  defp allowed?(:prepare_push, actor, changeset) do
    fields = Changeset.get_argument(changeset, :fields) || []

    with_link(
      actor,
      changeset,
      &Cases.can_push_github_advisory?(actor, &1, fields, %{}, validate?: true)
    )
  end

  defp allowed?(_action, _actor, _changeset), do: false

  defp with_case(actor, changeset, ask) do
    case Changeset.get_attribute(changeset, :case_id) do
      nil ->
        false

      case_id ->
        case Cases.get_case(case_id, actor: actor) do
          {:ok, case_record} -> ask.(case_record)
          {:error, _error} -> false
        end
    end
  end

  defp with_link(actor, changeset, ask) do
    case Changeset.get_argument(changeset, :link_id) do
      nil ->
        false

      link_id ->
        case Cases.get_github_advisory_link(link_id, actor: actor) do
          {:ok, link} -> ask.(link)
          {:error, _error} -> false
        end
    end
  end
end
