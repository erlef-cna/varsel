# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseReport do
  @moduledoc """
  A case citing a vulnerability report it came from.

  A report opens one case on submission. Splitting that case, or merging
  another case into it, adds further citations, so the cases one report led
  to stay traceable.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource]

  alias Varsel.Cases.Case
  alias Varsel.Cases.VulnerabilityReport

  postgres do
    table "case_reports"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :vulnerability_report, on_delete: :delete
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

  # Citations are read and written only through `cases` and
  # `vulnerability_reports`.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingCodeInterface
  actions do
    defaults [:read]

    create :cite do
      description "Records that a case cites a report. Citing it again changes nothing."
      primary? true
      accept [:case_id, :vulnerability_report_id]
      upsert? true
      upsert_identity :unique_case_report
      upsert_condition expr(false)
      return_skipped_upsert? true
    end
  end

  policies do
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    # The case's intake writes the first citation, and split and merge the
    # others. Each of their own policies decided on the cases.
    policy action_type(:create) do
      authorize_if accessing_from(Case, :vulnerability_reports_join_assoc)
    end
  end

  attributes do
    uuid_primary_key :id
    timestamps()
  end

  relationships do
    belongs_to :case, Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :vulnerability_report, VulnerabilityReport do
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_case_report, [:case_id, :vulnerability_report_id]
  end
end
