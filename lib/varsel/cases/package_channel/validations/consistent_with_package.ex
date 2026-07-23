# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Validations.ConsistentWithPackage do
  @moduledoc """
  Channel consistency rules:

  * `name` is required for every purl type except `:hosted` (a hosted
    service has no package identity).
  * The channel's denormalized `case_id` must match its parent
    `affected_package`'s `case_id` (rejects cross-case row mixups).
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    with {:ok, package} <- fetch_package(changeset),
         :ok <- validate_package_name(changeset, package) do
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

  defp validate_package_name(changeset, _package) do
    purl_type = Ash.Changeset.get_attribute(changeset, :purl_type)
    name = Ash.Changeset.get_attribute(changeset, :name)

    if purl_type != :hosted and is_nil(name) do
      {:error, field: :name, message: "is required for %{type} channels", vars: [type: purl_type]}
    else
      :ok
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
