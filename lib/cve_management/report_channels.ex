defmodule CveManagement.ReportChannels do
  @moduledoc false
  use Ash.Domain, otp_app: :cve_management, extensions: [AshAdmin.Domain]

  admin do
    show? true
  end

  resources do
    resource CveManagement.ReportChannels.EmailMessage
    resource CveManagement.ReportChannels.GitHubReport
    resource CveManagement.ReportChannels.ApiReport
  end
end
