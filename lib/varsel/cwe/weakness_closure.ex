# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.WeaknessClosure.OkResult do
  @moduledoc false
  use Ash.Type.Enum, values: [:ok]
end

defmodule Varsel.CWE.WeaknessClosure do
  @moduledoc """
  Transitive closure of `child_of` weakness relationships, scoped per CWE view.

  Backed by the `cwe_weakness_closure` materialized view (hand-written
  migration; this resource sets `migrate? false`). Each row means: within
  `view_id`, `descendant_cwe_id` is reachable from `parent_cwe_id` by walking
  `child_of` edges child-to-parent-to-child (or is `parent_cwe_id` itself —
  every CWE is a member of its own subtree).

  `parent_cwe_id` is `nil` for view-root rows. A `nil` parent behaves exactly
  like any other parent: its closure recursively covers every CWE reachable
  from any of the view's declared members, not just the members themselves.
  Counting CVEs under a NULL-parent row therefore counts the whole view.

  Refresh via the `:refresh` action, wired into `Varsel.CWE.CatalogSync` so
  every catalog import keeps the closure in sync with the underlying
  relationships and view memberships.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CWE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  alias Varsel.CWE.View
  alias Varsel.CWE.Weakness
  alias Varsel.CWE.WeaknessClosure.OkResult

  postgres do
    table "cwe_weakness_closure"
    repo Varsel.Repo
    migrate? false
  end

  resource do
    # parent_cwe_id is nil on view-root rows, so no attribute combination is
    # unique-and-non-null enough to serve as a primary key; this resource is
    # read/refresh-only over a materialized view, so it doesn't need one.
    require_primary_key? false
  end

  actions do
    read :read do
      primary? true
      description "Reads rows from the CWE weakness closure materialized view."
    end

    action :refresh, OkResult do
      description "Refreshes the cwe_weakness_closure materialized view."

      # Keeps reads of the view unblocked while it rebuilds; requires the
      # unique index created in the migration.
      run fn _input, _context ->
        Varsel.Repo.query!("REFRESH MATERIALIZED VIEW CONCURRENTLY cwe_weakness_closure")
        {:ok, :ok}
      end
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if always()
    end
  end

  # Derived, read-only materialized-view rows with no independent lifecycle —
  # per-row created/updated timestamps carry no meaning.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
  attributes do
    attribute :view_id, :integer do
      allow_nil? false
      writable? false
      public? true
    end

    attribute :parent_cwe_id, :integer do
      allow_nil? true
      writable? false
      public? true
      description "nil marks a view-root row; the closure of nil covers the whole view."
    end

    attribute :descendant_cwe_id, :integer do
      allow_nil? false
      writable? false
      public? true
    end
  end

  relationships do
    belongs_to :view, View do
      source_attribute :view_id
      destination_attribute :view_id
      define_attribute? false
      allow_nil? false
      public? true
    end

    belongs_to :parent, Weakness do
      source_attribute :parent_cwe_id
      destination_attribute :cwe_id
      define_attribute? false
      allow_nil? true
      public? true
    end

    belongs_to :descendant, Weakness do
      source_attribute :descendant_cwe_id
      destination_attribute :cwe_id
      define_attribute? false
      allow_nil? false
      public? true
    end
  end
end
