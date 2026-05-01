# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

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
