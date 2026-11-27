# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseMetric do
  @moduledoc """
  A CVSS v4.0 score of the case for one scenario, rendered into `metrics[]`.

  The `GENERAL` scenario is the score that applies when no more specific
  scenario matches. It sets the case's severity, and a case needs one to
  publish. Other scenarios describe, in plain text, the conditions under
  which their own score applies.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Cases.Changes.ApplyProposedField
  alias Varsel.Cases.Proposable
  alias Varsel.Cases.Signals

  @general "GENERAL"

  graphql do
    type :case_metric
  end

  postgres do
    table "case_metrics"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes [:inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    create :add do
      description "Scores the case for one scenario."
      primary? true
      accept [:case_id | Proposable.fields(__MODULE__)]
    end

    update :edit do
      description "Edits a scenario score. Only allowed while the case is editable."
      primary? true
      accept Proposable.fields(__MODULE__)
      require_atomic? false
    end

    destroy :remove do
      description "Removes a scenario score."
      primary? true
      require_atomic? false
      emit Signals, :proposal_target_destroyed, fields: [target_id: :id]
    end

    update :apply_proposal do
      description "Internal: applies one accepted proposal value to a single field."
      accept []
      require_atomic? false

      argument :field, :string, allow_nil?: false
      argument :value, :term
      argument :proposal_id, :uuid, allow_nil?: false
      change ApplyProposedField
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id | Proposable.fields(__MODULE__)]

      argument :proposal_id, :uuid, allow_nil?: false
    end

    destroy :apply_proposal_delete do
      description "Internal: removes the row targeted by an accepted :delete proposal."
      require_atomic? false

      argument :proposal_id, :uuid, allow_nil?: false

      emit Signals, :proposal_target_destroyed,
        fields: [target_id: :id],
        values: [driving_proposal_id: arg(:proposal_id)]
    end
  end

  policies do
    policy action_type(:read) do
      authorize_if AshOban.Checks.AshObanInteraction
      authorize_if expr(case.can_read(actor_id: ^actor(:id), actor_role: ^actor(:role)))
    end

    # Writing a case's facts is editing the case, so it needs a role as
    # well as an assignment — an assigned collaborator proposes instead.
    policy action_type([:create, :update, :destroy]) do
      authorize_if actor_attribute_equals(:role, :poc)
      forbid_unless actor_attribute_equals(:role, :supporter)
      authorize_if expr(exists(case, can_edit(actor_id: ^actor(:id), actor_role: ^actor(:role))))
    end

    # Content freeze: child rows may only change while the parent case is
    # editable, or when a POC corrects an approved one.
    policy action_type([:create, :update, :destroy]) do
      authorize_if expr(exists(case, content_editable(actor_role: ^actor(:role))))
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case"

    publish_all :create, [[:case_id]]
    publish_all :update, [[:case_id]]
    publish_all :destroy, [[:case_id]]
  end

  attributes do
    uuid_primary_key :id

    attribute :scenario, :string do
      description """
      Plain text naming the conditions this score applies to. GENERAL is the
      score that applies when no more specific scenario matches. The schema
      caps it at 4096 characters.
      """

      allow_nil? false
      default @general
      constraints max_length: 4096
      public? true
    end

    attribute :cvss_v4, Varsel.Types.CVSS do
      description "CVSS v4.0 vector. Score/severity/full metric object are derived at render time."
      allow_nil? false
      constraints version: [:v4]
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, Varsel.Cases.Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  calculations do
    calculate :general, :boolean, expr(scenario == @general) do
      description "Whether this is the GENERAL scenario."
      public? true
    end

    # An explicit collation, so the database orders scenarios the way `sort/1`
    # does whatever the server's locale.
    calculate :scenario_order, :string, expr(fragment("lower(?) COLLATE \"C\"", scenario)) do
      description "The scenario text as it sorts: case-insensitive, then byte order."
    end
  end

  identities do
    identity :unique_case_scenario, [:case_id, :scenario]
  end

  @doc "The scenario whose score applies when no more specific one matches."
  @spec general_scenario() :: String.t()
  def general_scenario, do: @general

  @doc "Orders metrics as a case lists them: GENERAL first, then the scenarios alphabetically."
  @spec sort([t]) :: [t] when t: %{scenario: String.t() | nil}
  def sort(metrics) do
    Enum.sort_by(
      metrics,
      &{&1.scenario != @general, String.downcase(&1.scenario || ""), &1.scenario || ""}
    )
  end
end
