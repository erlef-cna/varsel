# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub do
  @moduledoc """
  The GitHub App's credentials: which installations of the App exist, which
  of them a person reaches, and the installation tokens minted for them.

  Each `can_*?` function that the code interface generates is a permission
  question. `can_installation_token?(actor)` asks whether the actor may act
  as the App.
  """

  use Ash.Domain, otp_app: :varsel

  alias Varsel.GitHub.Installation
  alias Varsel.GitHub.InstallationLookup
  alias Varsel.GitHub.UserInstallation

  resources do
    resource Installation do
      define :installation_for_repository,
        action: :for_repository,
        args: [:owner, :repo],
        get?: true,
        not_found_error?: false

      define :installation_for_org,
        action: :for_org,
        args: [:account],
        get?: true,
        not_found_error?: false

      define :installation_token, action: :token, args: [:installation_id]
      define :public_read_token, action: :public_read_token
    end

    resource InstallationLookup

    resource UserInstallation do
      define :user_installations, action: :for_actor
    end
  end
end
