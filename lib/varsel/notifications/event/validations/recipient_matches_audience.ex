# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Event.Validations.RecipientMatchesAudience do
  @moduledoc """
  Validates that `recipient_id` is set exactly when the event's kind audience
  is `:recipient`, and nil otherwise.
  """

  use Ash.Resource.Validation

  alias Varsel.Notifications.Kind

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    case Ash.Changeset.get_attribute(changeset, :kind) do
      kind when not is_nil(kind) ->
        recipient_id = Ash.Changeset.get_attribute(changeset, :recipient_id)

        case {Kind.audience(kind), recipient_id} do
          {:recipient, nil} ->
            {:error, field: :recipient_id, message: "is required for kind #{kind}"}

          {audience, recipient_id} when audience != :recipient and not is_nil(recipient_id) ->
            {:error, field: :recipient_id, message: "must be nil for kind #{kind}"}

          _match ->
            :ok
        end

      # A nil kind fails allow_nil? false on its own; nothing to check here.
      nil ->
        :ok
    end
  end
end
