# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Predisclosure do
  @moduledoc """
  Pre-disclosure lists: named groups of users who see the cases a POC shares
  with the group before those cases are published.
  """

  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain, AshGraphql.Domain, AshPaperTrail.Domain]

  alias Varsel.Predisclosure.ListMember
  alias Varsel.Predisclosure.ListSubscriber
  alias Varsel.Predisclosure.PredisclosureList

  admin do
    show? true
  end

  graphql do
    queries do
      list PredisclosureList, :list_predisclosure_lists, :list
      get PredisclosureList, :get_predisclosure_list, :read
    end

    mutations do
      create PredisclosureList, :create_predisclosure_list, :create
      update PredisclosureList, :rename_predisclosure_list, :rename
      destroy PredisclosureList, :destroy_predisclosure_list, :destroy
      create ListSubscriber, :subscribe_to_predisclosure_list, :subscribe
      destroy ListSubscriber, :unsubscribe_from_predisclosure_list, :unsubscribe
    end
  end

  paper_trail do
    include_versions? true
  end

  resources do
    resource PredisclosureList do
      define :list_predisclosure_lists, action: :list
      define :get_predisclosure_list, action: :read, get_by: [:id]
      define :create_predisclosure_list, action: :create, args: [:name]
      define :rename_predisclosure_list, action: :rename, args: [:name]
      define :destroy_predisclosure_list, action: :destroy
    end

    resource ListSubscriber do
      define :subscribe_to_predisclosure_list, action: :subscribe, args: [:list_id, :user_id]
      define :unsubscribe_from_predisclosure_list, action: :unsubscribe
      define :list_predisclosure_list_subscribers, action: :read
    end

    resource ListMember do
      define :list_predisclosure_list_members, action: :read
    end
  end
end
