# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Validations.ConsistentWithPackage do
  @moduledoc """
  Channel consistency rules: the identity rules of
  `Varsel.Cases.PackageChannel.Validations.ConsistentIdentity`, plus a check
  that the channel's denormalized `case_id` matches its parent
  `affected_package`'s (which rejects cross-case row mixups).
  """

  use Ash.Resource.Validation

  alias Ash.Resource.Validation
  alias Varsel.Cases.PackageChannel.Validations.ConsistentIdentity

  @impl Validation
  def validate(changeset, opts, context) do
    with :ok <- ConsistentIdentity.validate(changeset, opts, context) do
      validate_same_case(changeset)
    end
  end

  # A channel created through its package's `:channels` relationship has both
  # ids stamped by Ash *after* validation, and they agree by construction.
  # Presence itself is the relationship's `allow_nil? false` to enforce, not
  # ours.
  defp validate_same_case(changeset) do
    case Ash.Changeset.get_attribute(changeset, :affected_package_id) do
      nil -> :ok
      affected_package_id -> compare_case(changeset, affected_package_id)
    end
  end

  defp compare_case(changeset, affected_package_id) do
    case Varsel.Cases.get_affected_package(affected_package_id, authorize?: false) do
      {:ok, package} ->
        if package.case_id == Ash.Changeset.get_attribute(changeset, :case_id) do
          :ok
        else
          {:error, field: :affected_package_id, message: "belongs to a different case"}
        end

      {:error, _not_found} ->
        {:error, field: :affected_package_id, message: "does not exist"}
    end
  end
end
