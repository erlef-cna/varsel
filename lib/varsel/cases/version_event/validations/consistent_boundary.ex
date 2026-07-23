# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.VersionEvent.Validations.ConsistentBoundary do
  @moduledoc """
  Boundary-fact consistency rules:

  * At least one of `commit_sha` / `version` must be set.
  * The denormalized `case_id` must match the parent package's `case_id`.
  * A channel-scoped fact's channel must belong to the same package.
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    with :ok <- validate_boundary(changeset),
         :ok <- validate_same_case(changeset) do
      validate_channel_of_package(changeset)
    end
  end

  defp validate_boundary(changeset) do
    commit_sha = Ash.Changeset.get_attribute(changeset, :commit_sha)
    version = Ash.Changeset.get_attribute(changeset, :version)

    if is_nil(commit_sha) and is_nil(version) do
      {:error, field: :commit_sha, message: "either commit_sha or version must be set"}
    else
      :ok
    end
  end

  defp validate_same_case(changeset) do
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)
    affected_package_id = Ash.Changeset.get_attribute(changeset, :affected_package_id)

    with false <- is_nil(case_id) or is_nil(affected_package_id),
         {:ok, %{case_id: package_case_id}} <-
           Varsel.Cases.get_affected_package(affected_package_id, authorize?: false),
         false <- package_case_id == case_id do
      {:error, field: :affected_package_id, message: "belongs to a different case"}
    else
      true -> :ok
      {:error, _} -> {:error, field: :affected_package_id, message: "does not exist"}
    end
  end

  defp validate_channel_of_package(changeset) do
    package_channel_id = Ash.Changeset.get_attribute(changeset, :package_channel_id)
    affected_package_id = Ash.Changeset.get_attribute(changeset, :affected_package_id)

    with false <- is_nil(package_channel_id),
         {:ok, %{affected_package_id: channel_package_id}} <-
           Varsel.Cases.get_package_channel(package_channel_id, authorize?: false),
         false <- channel_package_id == affected_package_id do
      {:error, field: :package_channel_id, message: "belongs to a different package"}
    else
      true -> :ok
      {:error, _} -> {:error, field: :package_channel_id, message: "does not exist"}
    end
  end
end
