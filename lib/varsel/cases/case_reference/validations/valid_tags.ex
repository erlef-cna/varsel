# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseReference.Validations.ValidTags do
  @moduledoc """
  Validates reference tags against the CVE 5.2 vocabulary, allowing
  `x_`-prefixed custom tags (EEF uses `x_version-scheme`).
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, opts, _context) do
    allowed = Keyword.fetch!(opts, :allowed)
    tags = Ash.Changeset.get_attribute(changeset, :tags) || []

    case Enum.reject(tags, &(&1 in allowed or String.starts_with?(&1, "x_"))) do
      [] ->
        :ok

      invalid ->
        {:error,
         field: :tags, message: "contains invalid reference tags: %{invalid}", vars: [invalid: Enum.join(invalid, ", ")]}
    end
  end
end
