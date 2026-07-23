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
  alias Varsel.CVE.VulnerabilityReport

  admin do
    show? true
  end

  tools do
    tool :list_cves, CveRecord, :list_published do
      load [:cve_id, :title, :date_published, :date_updated, :purls]
    end

    tool :get_cve, CveRecord, :get_published do
      load [:cve_id, :title, :date_published, :date_updated, :purls]
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

    tool :list_osv_records, OsvRecord, :read
    tool :get_osv_record, OsvRecord, :get

    tool :submit_vulnerability_report, VulnerabilityReport, :submit

    # POC-only lifecycle tooling (policy-gated; requires an API key actor).
    tool :list_all_cves, CveRecord, :list_all do
      load [:cve_id, :title, :date_published, :date_updated, :purls]
    end

    tool :available_cve_ids, CveRecord, :available do
      load [:cve_id]
    end

    tool :assign_cve, CveRecord, :assign
    tool :update_cve, CveRecord, :update
    tool :request_publish_cve, CveRecord, :request_publish
    tool :reject_cve, CveRecord, :reject
  end

  graphql do
    queries do
      list CveRecord, :list_published_cves, :list_published
      get CveRecord, :get_published_cve, :get_published, identity: false
      list CveRecord, :search_cves, :search
      list CveRecord, :list_cves_by_purl, :list_by_purl

      # POC-only (policy-gated; anonymous callers see published records only).
      list CveRecord, :list_all_cves, :list_all
      list CveRecord, :available_cve_ids, :available

      list OsvRecord, :list_osv_records, :read
      read_one OsvRecord, :get_osv_record, :get

      # POC-only report triage (policy-gated).
      list VulnerabilityReport, :list_vulnerability_reports, :list_reports

      action CveValidation, :validate_cve, :validate
      action CveValidation, :validate_cve_schema, :validate_schema
      action CveValidation, :validate_cve_cvelint, :validate_cvelint
      action CveValidation, :validate_cve_hex_packages, :validate_hex_packages
    end

    mutations do
      create VulnerabilityReport, :submit_vulnerability_report, :submit

      # POC-only report triage (policy-gated). Accepting without a case_id
      # opens a fresh draft case titled from the report summary.
      update VulnerabilityReport, :triage_vulnerability_report, :triage
      update VulnerabilityReport, :accept_vulnerability_report, :accept
      update VulnerabilityReport, :reject_vulnerability_report, :reject

      # POC-only lifecycle transitions (policy-gated).
      update CveRecord, :assign_cve, :assign
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
      define :get_published_cve_record, action: :get_published, args: [:cve_id]
      define :search_cve_records, action: :search, args: [:query]

      # Admin (POC-only) lifecycle management, used by the CVE-management LiveView.
      define :list_all_cve_records, action: :list_all
      define :get_cve_record, action: :read, get_by: [:id]
      define :assign_cve_record, action: :assign
      define :request_publish_cve_record, action: :request_publish
      define :update_cve_record, action: :update
      define :reject_cve_record, action: :reject
    end

    resource CveValidation do
      define :validate_cve_record, action: :validate, args: [:cve_json]
    end

    resource OsvRecord do
      define :list_osv_feed, action: :list_feed
      define :get_osv_record, action: :get, args: [:osv_id]
    end

    resource VulnerabilityReport do
      define :submit_vulnerability_report, action: :submit

      # POC-only triage, used by the (future) report-management LiveView.
      define :list_vulnerability_reports, action: :list_reports
      define :get_vulnerability_report, action: :read, get_by: [:id]
      define :triage_vulnerability_report, action: :triage
      define :accept_vulnerability_report, action: :accept
      define :reject_vulnerability_report, action: :reject
    end
  end
end
