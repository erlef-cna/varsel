# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Validations.ConsistentWithPackage do
  @moduledoc """
  Channel consistency rules:

  * `package_name` is required for every channel type except `:hosted` and
    `:git` — a git channel derives its path from the package's `repo_url`.
  * A `:git` channel needs the package to have a `repo_url` (the repository
    is what its commit ranges resolve against).
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
        case Ash.get(Varsel.Cases.AffectedPackage, affected_package_id, authorize?: false) do
          {:ok, package} -> {:ok, package}
          {:error, _} -> {:error, field: :affected_package_id, message: "does not exist"}
        end
    end
  end

  defp validate_package_name(changeset, package) do
    channel_type = Ash.Changeset.get_attribute(changeset, :channel_type)
    package_name = Ash.Changeset.get_attribute(changeset, :package_name)

    cond do
      channel_type == :git and is_nil(package.repo_url) ->
        {:error, field: :channel_type, message: "a git channel needs a repository URL on the package"}

      channel_type in [:hosted, :git] ->
        :ok

      is_nil(package_name) ->
        {:error, field: :package_name, message: "is required for %{type} channels", vars: [type: channel_type]}

      true ->
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
