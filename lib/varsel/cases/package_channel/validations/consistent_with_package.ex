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
    with {:ok, package} <- fetch_package(changeset),
         :ok <- ConsistentIdentity.validate(changeset, opts, context) do
      validate_same_case(changeset, package)
    end
  end

  defp fetch_package(changeset) do
    case Ash.Changeset.get_attribute(changeset, :affected_package_id) do
      nil ->
        {:error, field: :affected_package_id, message: "is required"}

      affected_package_id ->
        case Varsel.Cases.get_affected_package(affected_package_id, authorize?: false) do
          {:ok, package} -> {:ok, package}
          {:error, _} -> {:error, field: :affected_package_id, message: "does not exist"}
        end
    end
  end

  defp validate_same_case(changeset, package) do
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)

    if package.case_id == case_id do
      :ok
    else
      {:error, field: :affected_package_id, message: "belongs to a different case"}
    end
  end
end
