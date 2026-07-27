# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.VersionActorReference do
  @moduledoc """
  Keeps a paper-trail version's actor id without a foreign key to the account.

  A version records who made a change, and that stays true after the account is
  deleted — the id is the only thing tying an entry in the audit trail to
  whoever caused it. A foreign key would force the choice between refusing the
  deletion and nulling the trail, and both lose something worth keeping.

  `belongs_to_actor` offers only `on_delete`, so the reference it generates is
  replaced here with an ignored one. The column and the relationship are
  untouched; only the constraint goes. Loading `:user` on a version whose
  account is gone returns nil, which is the same answer a nulled column would
  give — the difference is that the id is still there to read.

  Used through `version_extensions` on every versioned resource that names an
  actor.
  """

  use Spark.Dsl.Extension, transformers: [__MODULE__.Transformer]

  defmodule Transformer do
    @moduledoc false

    use Spark.Dsl.Transformer

    alias Spark.Dsl.Transformer

    # After AshPostgres has built its references, so replacing one wins.
    @impl Transformer
    def after?(AshPostgres.DataLayer.Transformers.ValidateReferences), do: true
    def after?(_transformer), do: false

    @impl Transformer
    def transform(dsl_state) do
      {:ok,
       Enum.reduce(actor_relationships(dsl_state), dsl_state, fn name, dsl_state ->
         Transformer.replace_entity(
           dsl_state,
           [:postgres, :references],
           Transformer.build_entity!(AshPostgres.DataLayer, [:postgres, :references], :reference,
             relationship: name,
             ignore?: true
           ),
           &(&1.relationship == name)
         )
       end)}
    end

    # The version's own belongs_to relationships that point at a user: the
    # actor, whatever it was named.
    defp actor_relationships(dsl_state) do
      dsl_state
      |> Transformer.get_entities([:relationships])
      |> Enum.filter(&(&1.type == :belongs_to and &1.destination == Varsel.Accounts.User))
      |> Enum.map(& &1.name)
    end
  end
end
