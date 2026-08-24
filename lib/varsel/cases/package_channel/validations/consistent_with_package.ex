# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Validations.ConsistentWithPackage do
  @moduledoc """
  Rejects a channel whose denormalized `case_id` disagrees with its parent
  `affected_package`'s — a cross-case row mixup.

  How the channel names itself is
  `Varsel.Cases.PackageChannel.Validations.ConsistentIdentity`'s business,
  declared separately on the resource.
  """

  use Ash.Resource.Validation

  alias Ash.Resource.Validation

  @impl Validation
  def validate(changeset, _opts, context) do
    # A channel created through its package's `:channels` relationship has both
    # ids stamped by Ash *after* validation, and they agree by construction.
    # Presence itself is the relationship's `allow_nil? false` to enforce.
    case Ash.Changeset.get_attribute(changeset, :affected_package_id) do
      nil -> :ok
      affected_package_id -> compare_case(changeset, affected_package_id, context)
    end
  end

  defp compare_case(changeset, affected_package_id, context) do
    case Varsel.Cases.get_affected_package(affected_package_id, Ash.Context.to_opts(context)) do
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
