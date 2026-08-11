# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Validations.ConsistentIdentity do
  @moduledoc """
  A channel names itself exactly one way, per its `kind`:

  * `:package` needs a `purl_type` and a `name`, and carries no `domain`.
  * `:service` needs a `domain` and none of the purl fields.

  Shared by `Varsel.Cases.PackageChannel` and the
  `Varsel.Cases.PackageChannel.ChannelInput` embedded in package proposals, so
  a channel authored inline is rejected at propose time by the same rules that
  govern the stored row.
  """

  use Ash.Resource.Validation

  alias Ash.Resource.Validation

  @package_only [:purl_type, :namespace, :name, :qualifiers, :subpath]

  @impl Validation
  def validate(changeset, _opts, _context) do
    case Ash.Changeset.get_attribute(changeset, :kind) do
      :service -> validate_service(changeset)
      _package -> validate_package(changeset)
    end
  end

  defp validate_package(changeset) do
    cond do
      blank?(changeset, :purl_type) ->
        {:error, field: :purl_type, message: "is required for package channels"}

      blank?(changeset, :name) ->
        {:error, field: :name, message: "is required for package channels"}

      not blank?(changeset, :domain) ->
        {:error, field: :domain, message: "is only set on service channels"}

      true ->
        :ok
    end
  end

  defp validate_service(changeset) do
    cond do
      blank?(changeset, :domain) ->
        {:error, field: :domain, message: "is required for service channels"}

      set_field = Enum.find(@package_only, &(not blank?(changeset, &1))) ->
        {:error, field: set_field, message: "is not set on service channels (they have no purl)"}

      true ->
        :ok
    end
  end

  defp blank?(changeset, field) do
    Ash.Changeset.get_attribute(changeset, field) in [nil, "", %{}, []]
  end
end
