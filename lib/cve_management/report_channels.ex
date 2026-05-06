# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels do
  @moduledoc false
  use Ash.Domain, otp_app: :cve_management, extensions: [AshAdmin.Domain]

  admin do
    show? true
  end

  resources do
    resource CveManagement.ReportChannels.EmailMessage
    resource CveManagement.ReportChannels.GitHubAdvisory
    resource CveManagement.ReportChannels.GitHubAdvisoryWeakness
    resource CveManagement.ReportChannels.GitHubWatchedTarget
    resource CveManagement.ReportChannels.ApiReport
  end
end
