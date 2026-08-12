# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE do
  @moduledoc false
  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain, AshAi, AshGraphql.Domain, AshPaperTrail.Domain]

  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.CveValidation
  alias Varsel.CVE.OsvRecord
  alias Varsel.CVE.ReportParticipant
  alias Varsel.CVE.VulnerabilityReport

  admin do
    show? true
  end

  tools do
    tool :list_cves, CveRecord, :list_published do
      load [:cve_id, :title, :date_published, :date_updated, :purls]
    end

    tool :get_cve, CveRecord, :read do
      get_by :cve_id
      load [:cve_id, :title, :date_published, :date_updated, :purls]
    end

    tool :validate_cve, CveRecord, :read do
      get_by :cve_id
      load [:cve_id, :validation]
    end

    tool :search_cves, CveRecord, :search do
      load [:cve_id, :title, :date_published, :date_updated, :purls]
    end

    tool :list_cves_by_purl, CveRecord, :list_by_purl do
      load [:cve_id, :title, :date_published, :date_updated, :purls]
    end

    tool :validate_cve_record, CveValidation, :validate
    tool :validate_cve_record_schema, CveValidation, :validate_schema
    tool :validate_cve_record_cvelint, CveValidation, :validate_cvelint
    tool :validate_cve_record_hex_packages, CveValidation, :validate_hex_packages
    tool :validate_cve_record_eef, CveValidation, :validate_eef

    tool :list_osv_records, OsvRecord, :read

    tool :get_osv_record, OsvRecord, :read do
      get_by :osv_id
    end

    tool :submit_vulnerability_report, VulnerabilityReport, :submit

    # POC-only lifecycle tooling (policy-gated; requires an API key actor).
    tool :list_all_cves, CveRecord, :list_all do
      load [:cve_id, :title, :date_published, :date_updated, :purls]
    end

    tool :available_cve_ids, CveRecord, :available do
      load [:cve_id]
    end

    tool :assign_cve, CveRecord, :assign
    tool :withhold_cve, CveRecord, :withhold
    tool :update_cve, CveRecord, :update
    tool :request_publish_cve, CveRecord, :request_publish
    tool :reject_cve, CveRecord, :reject
  end

  graphql do
    queries do
      list CveRecord, :list_published_cves, :list_published
      get CveRecord, :get_cve_record, :read, identity: :unique_cve_id
      list CveRecord, :search_cves, :search
      list CveRecord, :list_cves_by_purl, :list_by_purl
      list CveRecord, :list_all_cves, :list_all
      list CveRecord, :available_cve_ids, :available

      list OsvRecord, :list_osv_records, :read
      get OsvRecord, :get_osv_record, :read, identity: :unique_osv_id

      list VulnerabilityReport, :list_vulnerability_reports, :list_reports

      action CveValidation, :validate_cve, :validate
      action CveValidation, :validate_cve_schema, :validate_schema
      action CveValidation, :validate_cve_cvelint, :validate_cvelint
      action CveValidation, :validate_cve_hex_packages, :validate_hex_packages
      action CveValidation, :validate_cve_eef, :validate_eef
    end

    mutations do
      create VulnerabilityReport, :submit_vulnerability_report, :submit
      update VulnerabilityReport, :triage_vulnerability_report, :triage
      update VulnerabilityReport, :accept_vulnerability_report, :accept
      update VulnerabilityReport, :reject_vulnerability_report, :reject
      update VulnerabilityReport, :withdraw_vulnerability_report, :withdraw

      update CveRecord, :assign_cve, :assign
      update CveRecord, :withhold_cve, :withhold
      update CveRecord, :update_cve, :update
      update CveRecord, :request_publish_cve, :request_publish
      update CveRecord, :reject_cve, :reject
    end
  end

  paper_trail do
    include_versions? true
  end

  resources do
    resource CveRecord do
      define :import_cves_from_mitre, action: :import_from_mitre
      define :sync_reserved_cves_from_mitre, action: :sync_reserved_from_mitre
      define :list_published_cve_records, action: :list_published
      define :count_published_cve_records_by_quarter, action: :published_quarter_counts
      define :count_published_cve_records_by_cwe_subtree, action: :published_cwe_subtree_counts
      define :count_published_cve_records_in_cwe_view, action: :published_cwe_view_total
      define :get_cve_record_by_cve_id, action: :read, get_by: [:cve_id]
      define :search_cve_records, action: :search, args: [:query]
      define :list_cve_records_by_purl, action: :list_by_purl, args: [:purl]
      define :available_cve_records, action: :available, args: [:year]
      define :list_assignable_cve_records, action: :assignable

      # Reservation-pool + MITRE sync management.
      define :reserve_cve_record, action: :reserve
      define :import_cve_record, action: :import
      define :top_up_cve_pool, action: :top_up_pool
      define :run_reject_stale_cve_records, action: :run_reject_stale

      # Admin (POC-only) lifecycle management, used by the CVE-management LiveView.
      define :list_all_cve_records, action: :list_all
      define :get_cve_record, action: :read, get_by: [:id]
      define :assign_cve_record, action: :assign
      define :withhold_cve_record, action: :withhold
      define :request_publish_cve_record, action: :request_publish
      define :update_cve_record, action: :update
      define :publish_cve_record, action: :publish
      define :push_cve_record_update, action: :push_update
      define :sync_cve_record_from_mitre, action: :sync_from_mitre
      define :reject_cve_record, action: :reject
      define :mark_cve_record_rejected, action: :mark_rejected
    end

    resource CveValidation do
      define :validate_cve_record, action: :validate, args: [:cve_json]
      define :validate_cve_record_schema, action: :validate_schema, args: [:cve_json]
      define :validate_cve_record_cvelint, action: :validate_cvelint, args: [:cve_json]
      define :validate_cve_record_hex_packages, action: :validate_hex_packages, args: [:cve_json]
      define :validate_cve_record_eef, action: :validate_eef, args: [:cve_json]
    end

    resource OsvRecord do
      define :list_osv_records, action: :read
      define :list_osv_feed, action: :list_feed
      define :get_osv_record, action: :read, get_by: :osv_id
      define :create_osv_record, action: :create
      define :create_missing_osv_records, action: :create_missing
      define :sync_osv_record, action: :sync
    end

    resource VulnerabilityReport do
      define :submit_vulnerability_report, action: :submit
      define :list_vulnerability_reports, action: :list_reports
      define :get_vulnerability_report, action: :read, get_by: [:id]
      define :triage_vulnerability_report, action: :triage
      define :accept_vulnerability_report, action: :accept
      define :reject_vulnerability_report, action: :reject
      define :withdraw_vulnerability_report, action: :withdraw
      define :notify_pocs_of_vulnerability_report, action: :notify_pocs
      define :submit_hex_vulnerability_report, action: :submit_from_hex
      define :link_vulnerability_report_reporter, action: :link_reporter
    end

    resource ReportParticipant do
      define :list_report_participants, action: :read
      define :record_report_participant, action: :record

      define :list_report_participants_for_identity,
        action: :for_identity,
        args: [:strategy, :username]

      define :link_report_participant_user, action: :link_user
      define :spend_report_participant, action: :spend
    end
  end
end
