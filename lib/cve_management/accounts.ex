# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts do
  @moduledoc false
  use Ash.Domain,
    otp_app: :cve_management

  resources do
    resource CveManagement.Accounts.Token
    resource CveManagement.Accounts.User
  end
end
