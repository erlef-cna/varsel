# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment.Changes.MarkTriageRecommendation do
  @moduledoc """
  Opens a triage recommendation's body with the line that marks it as
  automated. The reporter reads the case's comments too, so the marker must
  not depend on the agent writing it.
  """

  use Ash.Resource.Change

  alias Ash.Changeset

  @marker "**Automated triage recommendation.** An agent wrote this for the CNA's triagers. A person at the CNA decides whether it accepts the case."

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    case Changeset.get_attribute(changeset, :body) do
      nil -> changeset
      body -> Changeset.force_change_attribute(changeset, :body, @marker <> "\n\n" <> body)
    end
  end
end
