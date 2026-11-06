# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CommentReaction.Validations.CommentBelongsToCase do
  @moduledoc """
  A reaction names the case of the comment it reacts to.
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, context) do
    comment_id = Ash.Changeset.get_attribute(changeset, :comment_id)
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)

    case Varsel.Cases.get_case_comment(comment_id, Ash.Context.to_opts(context)) do
      {:ok, %{case_id: ^case_id}} -> :ok
      {:ok, _comment} -> {:error, field: :comment_id, message: "belongs to a different case"}
      {:error, _error} -> {:error, field: :comment_id, message: "does not exist"}
    end
  end
end
