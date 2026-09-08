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
  the case is in draft or review.
  """

  use Ash.Policy.SimpleCheck

  alias Ash.Changeset
  alias Varsel.Cases

  @impl Ash.Policy.Check
  def describe(_opts), do: "the caller may edit the case"

  @impl Ash.Policy.SimpleCheck
  def match?(actor, %{subject: %Changeset{} = changeset}, _opts) do
    with case_id when is_binary(case_id) <- Changeset.get_attribute(changeset, :case_id),
         {:ok, case_record} <- Cases.get_case(case_id, actor: actor),
         {:ok, true} <- Cases.can_edit_case(actor, case_record, %{}, validate?: true) do
      true
    else
      _refused -> false
    end
  end

  def match?(_actor, _context, _opts), do: false
end
