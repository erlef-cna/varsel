# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts do
  @moduledoc false
  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain, AshAi, AshGraphql.Domain, AshPaperTrail.Domain]

  alias Varsel.Accounts.User

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
    resource Varsel.Accounts.ApiKey do
      define :list_api_keys, action: :read
      define :create_api_key, action: :create
      define :revoke_api_key, action: :destroy
    end

    resource Varsel.Accounts.Token

    resource User do
      define :list_users, action: :read
      define :update_user, action: :update
      define :set_user_role, action: :set_role, args: [:role]
      define :get_user_by_subject, action: :get_by_subject, args: [:subject]
      define :sign_in_user_with_api_key, action: :sign_in_with_api_key, args: [:api_key]
      define :register_user_with_github, action: :register_with_github
      define :register_user_with_hex, action: :register_with_hex
      define :set_user_notification_email, action: :set_notification_email
      define :merge_user_into, action: :merge_into, args: [:into]
      define :get_link_counterpart, action: :get_link_counterpart, args: [:id]
      define :log_out_user_everywhere, action: :log_out_everywhere

      # The mock sign-in action only exists in dev/test builds; see
      # Varsel.Accounts.User.
      if Mix.env() in [:dev, :test] do
        define :mock_sign_in_user, action: :mock_sign_in
      end
    end

    resource Varsel.Accounts.UserIdentity do
      define :unlink_provider, action: :destroy
    end

    resource Varsel.Accounts.OauthClient
    resource Varsel.Accounts.OauthAuthorizationCode
    resource Varsel.Accounts.OauthRefreshToken
    resource Varsel.Accounts.OauthConsent
  end
end
