# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE do
  @moduledoc false
  use Ash.Domain, otp_app: :cve_management, extensions: [AshAdmin.Domain, AshAi]

  alias CveManagement.CVE.CveRecord

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
  end

  resources do
    resource CveRecord do
      define :import_cves_from_mitre, action: :import_from_mitre
      define :list_published_cve_records, action: :list_published
      define :get_published_cve_record, action: :get_published, args: [:cve_id]
    end
  end
end
