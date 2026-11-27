# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Tlp do
  @moduledoc """
  The Traffic Light Protocol (TLP 2.0) marking of a case: how far the people
  who read the case may share what it says.

  The caveat holds extra sharing limits on top of the label, as the TLP 2.0
  user guide allows when no label fits.
  """

  @behaviour AshGraphql.Type

  use Ash.TypedStruct

  alias Varsel.Cases.Case.Tlp.Label

  typed_struct do
    field :label, Label, allow_nil?: false, default: :red, description: "The TLP 2.0 label."

    field :caveat, :string,
      constraints: [max_length: 2_000],
      description: "Extra sharing limits on top of the label, in plain text, e.g. who counts as the community."
  end

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_tlp

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_tlp_input
end
