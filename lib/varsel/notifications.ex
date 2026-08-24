# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications do
  @moduledoc false
  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain]

  alias Varsel.Notifications.Event
  alias Varsel.Notifications.Notification

  admin do
    show? true
  end

  resources do
    resource Notification do
      define :read_notifications, action: :read
      define :record_notification, action: :record
      define :list_notifications, action: :list_mine
      define :list_unread_notifications, action: :unread_mine
      define :mark_notification_read, action: :mark_read
      define :mark_notification_unread, action: :mark_unread

      define :mark_case_notifications_read,
        action: :mark_case_read,
        args: [:case_id],
        require_reference?: false,
        default_options: [
          bulk_options: [
            notify?: true,
            return_errors?: true,
            strategy: [:atomic, :atomic_batches, :stream]
          ]
        ]

      define :mark_kind_notifications_read,
        action: :mark_kind_read,
        args: [:kind],
        require_reference?: false,
        default_options: [
          bulk_options: [
            notify?: true,
            return_errors?: true,
            strategy: [:atomic, :atomic_batches, :stream]
          ]
        ]

      define :mark_notification_emailed, action: :mark_emailed
      define :send_notification_email, action: :send_email
      define :send_notification_digests, action: :send_digests
    end

    resource Event do
      define :emit_notification_event, action: :emit
      define :fan_out_notification_event, action: :fan_out
      define :read_notification_events, action: :read
    end
  end

  @doc "The acting user's unread notification count."
  @spec unread_notification_count(keyword()) :: integer()
  def unread_notification_count(opts) do
    opts
    |> query_to_list_unread_notifications()
    |> Ash.count!(actor: opts[:actor], tenant: opts[:tenant])
  end
end
