# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Validations.ValidTarget do
  @moduledoc """
  Creation-time validation of a proposal's polymorphic target:

  1. Shape: `field_name` iff `:set`; a `proposed_value` envelope iff
     `:set`/`:insert`; `target_id` rules per operation; `:insert`/`:delete`
     never address the case itself.
  2. Allowlist: the field / payload keys must be in
     `Varsel.Cases.Proposable`'s explicit lists.
  3. Types: `:set` values and `:insert` payload values are cast through the
     target attribute's real Ash type, so garbage never enters the queue.
  4. Existence & membership: a referenced row must exist and belong to the
     proposal's case (walking `Target.parent/1` for grandchildren).

  This is the UX gate; the `apply_proposal*` actions re-validate everything
  inside the accept transaction, so drift between propose and accept time is
  harmless.
  """

  use Ash.Resource.Validation

  alias Ash.Resource.Info
  alias Varsel.Cases.Proposable
  alias Varsel.Cases.Proposal.Target

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    target = Ash.Changeset.get_attribute(changeset, :target)
    target_id = Ash.Changeset.get_attribute(changeset, :target_id)
    operation = Ash.Changeset.get_attribute(changeset, :operation)

    if is_nil(target) or is_nil(operation) do
      # The attributes' own allow_nil? checks report these; dry runs (e.g.
      # `Ash.can?` probing with empty input) must not crash here.
      :ok
    else
      validate(changeset, target, target_id, operation)
    end
  end

  defp validate(changeset, target, target_id, operation) do
    field_name = Ash.Changeset.get_attribute(changeset, :field_name)
    proposed_value = Ash.Changeset.get_attribute(changeset, :proposed_value)
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)

    with :ok <- validate_shape(target, target_id, operation, field_name, proposed_value),
         :ok <- validate_value(target, operation, field_name, proposed_value) do
      validate_membership(target, target_id, operation, case_id)
    end
  end

  defp validate_shape(target, target_id, :set, field_name, proposed_value) do
    cond do
      is_nil(field_name) ->
        {:error, field: :field_name, message: "is required for :set proposals"}

      not envelope?(proposed_value) ->
        {:error, field: :proposed_value, message: "must be a %{\"value\" => ...} envelope"}

      target == :case and not is_nil(target_id) ->
        {:error, field: :target_id, message: "must be nil when targeting the case itself"}

      target != :case and is_nil(target_id) ->
        {:error, field: :target_id, message: "is required when targeting a child row"}

      true ->
        :ok
    end
  end

  defp validate_shape(target, target_id, :insert, field_name, proposed_value) do
    cond do
      not is_nil(field_name) ->
        {:error, field: :field_name, message: "is only allowed on :set proposals"}

      not envelope?(proposed_value) ->
        {:error, field: :proposed_value, message: "must be a %{\"value\" => ...} envelope"}

      target == :case ->
        {:error, field: :target, message: "the case itself cannot be inserted or deleted"}

      is_nil(target_id) and Target.parent(target) != :case ->
        {:error, field: :target_id, message: "must reference the parent row for this target"}

      not is_nil(target_id) and Target.parent(target) == :case ->
        {:error, field: :target_id, message: "must be nil; the parent of this target is the case"}

      true ->
        :ok
    end
  end

  defp validate_shape(target, target_id, :delete, field_name, proposed_value) do
    cond do
      not is_nil(field_name) ->
        {:error, field: :field_name, message: "is only allowed on :set proposals"}

      not is_nil(proposed_value) ->
        {:error, field: :proposed_value, message: "is not allowed on :delete proposals"}

      target == :case ->
        {:error, field: :target, message: "the case itself cannot be inserted or deleted"}

      is_nil(target_id) ->
        {:error, field: :target_id, message: "is required when targeting a child row"}

      true ->
        :ok
    end
  end

  defp envelope?(%{"value" => _value} = envelope) when map_size(envelope) == 1, do: true
  defp envelope?(_other), do: false

  defp validate_value(target, :set, field_name, %{"value" => value}) do
    resource = Target.resource(target)

    with {:ok, field} <- existing_field(resource, field_name, Proposable.set_fields(resource)) do
      cast_field(resource, field, value)
    end
  end

  defp validate_value(target, :insert, _field_name, %{"value" => payload}) when is_map(payload) do
    resource = Target.resource(target)
    allowed = Proposable.fields(resource) ++ Proposable.insert_extra_fields(resource)

    Enum.reduce_while(payload, :ok, fn entry, :ok ->
      case validate_payload_entry(resource, allowed, entry) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_value(_target, :insert, _field_name, _proposed_value) do
    {:error, field: :proposed_value, message: "an :insert payload must be a map of row fields"}
  end

  defp validate_value(_target, :delete, _field_name, _proposed_value), do: :ok

  defp validate_payload_entry(resource, allowed, {key, value}) do
    with {:ok, field} <- existing_field(resource, key, allowed) do
      cast_field(resource, field, value)
    end
  end

  defp existing_field(resource, name, allowed) do
    field = if is_atom(name), do: name, else: String.to_existing_atom(name)

    if field in allowed do
      {:ok, field}
    else
      {:error,
       field: :field_name,
       message: "%{name} is not a proposable field of %{resource}",
       vars: [name: name, resource: inspect(resource)]}
    end
  rescue
    ArgumentError ->
      {:error,
       field: :field_name,
       message: "%{name} is not a proposable field of %{resource}",
       vars: [name: name, resource: inspect(resource)]}
  end

  defp cast_field(resource, field, value) do
    attribute = Info.attribute(resource, field)

    with {:ok, cast} <- Ash.Type.cast_input(attribute.type, value, attribute.constraints),
         {:ok, _} <- Ash.Type.apply_constraints(attribute.type, cast, attribute.constraints) do
      :ok
    else
      _ ->
        {:error, field: :proposed_value, message: "%{field} does not accept the proposed value", vars: [field: field]}
    end
  end

  # Existence + case-membership: walk from the referenced row up to its case.
  defp validate_membership(_target, nil, _operation, _case_id), do: :ok

  defp validate_membership(target, target_id, operation, case_id) do
    # For :insert the target_id references the *parent* kind; else the row itself.
    referenced =
      case operation do
        :insert -> Target.parent(target)
        _other -> target
      end

    case Ash.get(Target.resource(referenced), target_id, authorize?: false) do
      {:ok, %{case_id: ^case_id}} ->
        :ok

      {:ok, _row} ->
        {:error, field: :target_id, message: "belongs to a different case"}

      {:error, _} ->
        {:error, field: :target_id, message: "does not exist"}
    end
  end
end
