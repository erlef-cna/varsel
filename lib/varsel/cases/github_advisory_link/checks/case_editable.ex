# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink.Checks.CaseEditable do
  @moduledoc """
  Whether the caller may edit the case a new link names, decided before the
  create runs any hook.

  A create decides a filter policy against the inserted row, after its hooks
  ran. The link's create reads GitHub in a hook, so the question goes to the
  case's own `:edit` policy up front: a POC or an assigned supporter, while
  the case is in draft or review. A changeset that names no case is
  undecidable here and gets `:unknown`. The question about a link that does
  not exist yet is `Varsel.Cases.can_edit_case?/4` on the case.
  """

  use Ash.Policy.Check

  alias Ash.Changeset
  alias Ash.Policy.Check
  alias Varsel.Cases

  @impl Check
  def type, do: :simple

  @impl Check
  def eager_evaluate?, do: true

  @impl Check
  def describe(_opts), do: "the caller may edit the case"

  @impl Check
  def strict_check(actor, %{subject: %Changeset{} = changeset}, _opts) do
    case Changeset.get_attribute(changeset, :case_id) do
      case_id when is_binary(case_id) -> {:ok, editable?(actor, case_id)}
      _none -> {:ok, :unknown}
    end
  end

  def strict_check(_actor, _context, _opts), do: {:ok, false}

  defp editable?(actor, case_id) do
    with {:ok, case_record} <- Cases.get_case(case_id, actor: actor),
         {:ok, true} <- Cases.can_edit_case(actor, case_record, %{}, validate?: true) do
      true
    else
      _refused -> false
    end
  end
end
