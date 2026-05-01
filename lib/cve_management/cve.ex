# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE do
  @moduledoc false
  use Ash.Domain, otp_app: :cve_management, extensions: [AshAdmin.Domain]

  admin do
    show? true
  end

  resources do
    resource CveManagement.CVE.CveReservation

    resource CveManagement.CVE.CveRecord do
      define :import_cves_from_mitre, action: :import_from_mitre
      define :list_published_cve_records, action: :list_published
      define :get_published_cve_record, action: :get_published, args: [:cve_id]
    end
  end
end
