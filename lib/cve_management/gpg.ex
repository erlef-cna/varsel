defmodule CveManagement.GPG do
  @moduledoc false
  use Ash.Domain, otp_app: :cve_management, extensions: [AshAdmin.Domain]

  admin do
    show? true
  end

  resources do
    resource CveManagement.GPG.ContactGpgKey
  end
end
