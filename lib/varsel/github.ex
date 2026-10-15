# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub do
  @moduledoc """
  The GitHub App's credentials: which installations of the App exist, which
  repositories they cover, which of them a person reaches, and the
  installation tokens minted for them.

  Each `can_*?` function that the code interface generates is a permission
  question. `can_installation_token?(actor)` asks whether the actor may act
  as the App.
  """

  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain]

  alias Varsel.GitHub.Installation
  alias Varsel.GitHub.InstallationRepository
  alias Varsel.GitHub.UserInstallation

  admin do
    show? true
  end

  resources do
    resource Installation do
      define :list_installations, action: :read
      define :get_installation, action: :read, get_by: [:id]

      define :installation_for_repository,
        action: :for_repository,
        args: [:owner, :repo],
        not_found_error?: false

      define :installation_for_account,
        action: :for_account,
        args: [:account],
        not_found_error?: false

      define :sync_installation, action: :sync
      define :forget_installation, action: :forget
      define :store_installation_token, action: :store_token
      define :sync_installations, action: :sync_all
      define :installation_token, action: :token, args: [:installation_id]
      define :public_read_token, action: :public_read_token
    end

    resource InstallationRepository do
      define :list_installation_repositories, action: :read
      define :sync_installation_repository, action: :sync
      define :forget_installation_repository, action: :forget
    end

    resource UserInstallation do
      define :list_user_installations, action: :read
      define :sync_user_installation, action: :sync
      define :forget_user_installation, action: :forget
    end
  end
end
