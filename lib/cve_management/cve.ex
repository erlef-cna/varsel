# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE do
  @moduledoc false
  use Ash.Domain,
    otp_app: :cve_management,
    extensions: [AshAdmin.Domain, AshAi, AshPaperTrail.Domain]

  alias CveManagement.CVE.CveRecord
  alias CveManagement.CVE.CveValidation
  alias CveManagement.CVE.OsvRecord

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
  end

  paper_trail do
    include_versions? true
  end

  resources do
    resource CveRecord do
      define :import_cves_from_mitre, action: :import_from_mitre
      define :list_published_cve_records, action: :list_published
      define :get_published_cve_record, action: :get_published, args: [:cve_id]
    end

    resource CveValidation do
      define :validate_cve_record, action: :validate, args: [:cve_json]
    end

    resource OsvRecord do
      define :list_osv_feed, action: :list_feed
      define :get_osv_record, action: :get, args: [:osv_id]
    end
  end
end
