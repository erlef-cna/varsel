# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Validations.CveIdAssignable do
  @moduledoc """
  A case may take a CVE ID once, while it is still being worked on.

  Both rules were preconditions inside
  `Varsel.Cases.Case.Changes.AssignCveRecord`, which meant they held at
  execution but were invisible to `Ash.can?/3` — a change does not run while
  authorizing, a validation does. Stating them here lets the workspace ask
  whether the button belongs on screen rather than restating the rule itself.
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    cond do
      changeset.data.state in [:published, :closed] ->
        {:error, field: :cve_record_id, message: "a %{state} case takes no CVE ID", vars: [state: changeset.data.state]}

      changeset.data.cve_record_id ->
        {:error, field: :cve_record_id, message: "the case already has a CVE ID assigned"}

      true ->
        :ok
    end
  end
end
