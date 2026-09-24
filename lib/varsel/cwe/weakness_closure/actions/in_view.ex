# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.WeaknessClosure.Actions.InView do
  @moduledoc """
  Answers whether a CWE is reachable from a view's root.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CWE.WeaknessClosure

  require Ash.Query

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    exists? =
      WeaknessClosure
      |> Ash.Query.filter(
        view_id == ^input.arguments.view_id and is_nil(parent_cwe_id) and
          descendant_cwe_id == ^input.arguments.cwe_id
      )
      |> Ash.exists?(Ash.Context.to_opts(context))

    {:ok, exists?}
  end
end
