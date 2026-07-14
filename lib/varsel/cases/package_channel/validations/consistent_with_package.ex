# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Validations.ConsistentWithPackage do
  @moduledoc """
  Channel consistency rules:

  * `package_name` is required for every channel type except `:hosted`.
  * The channel's denormalized `case_id` must match its parent
    `affected_package`'s `case_id` (rejects cross-case row mixups).
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    with :ok <- validate_package_name(changeset) do
      validate_same_case(changeset)
    end
  end

  defp validate_package_name(changeset) do
    channel_type = Ash.Changeset.get_attribute(changeset, :channel_type)
    package_name = Ash.Changeset.get_attribute(changeset, :package_name)

    if channel_type != :hosted and is_nil(package_name) do
      {:error, field: :package_name, message: "is required for %{type} channels", vars: [type: channel_type]}
    else
      :ok
    end
  end

  defp validate_same_case(changeset) do
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)
    affected_package_id = Ash.Changeset.get_attribute(changeset, :affected_package_id)

    with false <- is_nil(case_id) or is_nil(affected_package_id),
         {:ok, %{case_id: package_case_id}} <-
           Ash.get(Varsel.Cases.AffectedPackage, affected_package_id, authorize?: false),
         false <- package_case_id == case_id do
      {:error, field: :affected_package_id, message: "belongs to a different case"}
    else
      true -> :ok
      {:error, _} -> {:error, field: :affected_package_id, message: "does not exist"}
    end
  end
end
