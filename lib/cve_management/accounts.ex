# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts do
  @moduledoc false
  use Ash.Domain,
    otp_app: :cve_management,
    extensions: [AshAdmin.Domain, AshAi, AshGraphql.Domain, AshPaperTrail.Domain]

  alias CveManagement.Accounts.User

  admin do
    show? true
  end

  tools do
    tool :list_users, User, :read
    tool :update_user, User, :update
    tool :set_user_role, User, :set_role
  end

  graphql do
    queries do
      list User, :list_users, :read
    end

    mutations do
      update User, :update_user, :update
      update User, :set_user_role, :set_role
    end
  end

  paper_trail do
    include_versions? true
  end

  resources do
    resource CveManagement.Accounts.ApiKey do
      define :list_api_keys, action: :read
      define :create_api_key, action: :create
      define :revoke_api_key, action: :destroy
    end

    resource CveManagement.Accounts.Token

    resource User do
      define :list_users, action: :read
      define :set_user_role, action: :set_role, args: [:role]
    end

    resource CveManagement.Accounts.UserIdentity
  end
end
