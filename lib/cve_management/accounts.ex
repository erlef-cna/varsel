# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts do
  @moduledoc false
  use Ash.Domain,
    otp_app: :cve_management,
    extensions: [AshAdmin.Domain, AshPaperTrail.Domain]

  admin do
    show? true
  end

  paper_trail do
    include_versions? true
  end

  resources do
    resource CveManagement.Accounts.Token

    resource CveManagement.Accounts.User do
      define :list_users, action: :read
      define :set_user_role, action: :set_role, args: [:role]
    end

    resource CveManagement.Accounts.UserIdentity
  end
end
