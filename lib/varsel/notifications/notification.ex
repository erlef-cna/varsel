# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Notification do
  @moduledoc """
  One row per user, kind and subject (a case or a vulnerability report).

  Repeated events of the same kind on the same subject absorb into the
  subject's unread row: `:record` upserts on `unread_per_subject` and bumps
  `count`. Once the row is read, the next matching event starts a new row.

  `:record`, `:mark_emailed`, `:send_email` and `:send_digests` are reachable
  only through the AshOban bypass (the fan-out, email and digest workers).
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Notifications,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban],
    notifiers: [Ash.Notifier.PubSub]

  alias AshOban.Checks.AshObanInteraction
  alias Varsel.Accounts.User
  alias Varsel.Cases.Case
  alias Varsel.CVE.VulnerabilityReport
  alias Varsel.Notifications.Emails
  alias Varsel.Notifications.Kind
  alias Varsel.Types.OkResult

  require Ash.Query

  postgres do
    table "notifications"
    repo Varsel.Repo

    references do
      reference :user, on_delete: :delete
      reference :case, on_delete: :delete
      reference :vulnerability_report, on_delete: :delete
    end

    identity_wheres_to_sql unread_per_subject: "read_at IS NULL"
  end

  oban do
    triggers do
      trigger :email do
        action :send_email

        where expr(
                email_requested and is_nil(emailed_at) and is_nil(read_at) and
                  user.notification_email_mode == :immediate
              )

        worker_module_name Varsel.Notifications.Notification.EmailWorker
        scheduler_module_name Varsel.Notifications.Notification.EmailScheduler
        queue :default
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end

    scheduled_actions do
      schedule :send_digests, "0 7 * * *",
        action: :send_digests,
        worker_module_name: Varsel.Notifications.Notification.SendDigestsWorker,
        queue: :default,
        max_attempts: 3
    end
  end

  actions do
    read :read do
      description "Plain read, narrowed to the acting user's own rows by policy."
      primary? true
      pagination keyset?: true, required?: false
    end

    create :record do
      description "Records one event, absorbing it into the subject's unread row if one exists."
      primary? true
      accept [:kind, :user_id, :case_id, :vulnerability_report_id, :email_requested]

      upsert? true
      upsert_identity :unread_per_subject
      upsert_fields [:last_event_at, :email_requested]

      change set_attribute(:last_event_at, &DateTime.utc_now/0)
      change atomic_update(:count, expr(count + 1))
      change run_oban_trigger(:email)
    end

    read :list_mine do
      description "The acting user's notifications, most recent first."
      prepare build(sort: [last_event_at: :desc])

      pagination offset?: true,
                 keyset?: true,
                 countable: :by_default,
                 default_limit: 25,
                 required?: false
    end

    read :unread_mine do
      description "The acting user's unread notifications."
      filter expr(is_nil(read_at))
    end

    update :mark_read do
      description "Marks a notification as read."
      primary? true
      accept []
      change set_attribute(:read_at, &DateTime.utc_now/0)
    end

    update :mark_unread do
      description "Marks a notification as unread again."
      accept []
      change set_attribute(:read_at, nil)
    end

    update :mark_case_read do
      description "Marks the acting user's unread notifications for one case as read."
      accept []

      argument :case_id, :uuid, allow_nil?: false

      change filter(expr(case_id == ^arg(:case_id) and is_nil(read_at)))
      change set_attribute(:read_at, &DateTime.utc_now/0)
    end

    update :mark_kind_read do
      description "Marks the acting user's unread notifications of one kind as read."
      accept []

      argument :kind, Kind, allow_nil?: false

      change filter(expr(kind == ^arg(:kind) and is_nil(read_at)))
      change set_attribute(:read_at, &DateTime.utc_now/0)
    end

    update :mark_emailed do
      description "Stamps the notification as emailed."
      accept []
      change set_attribute(:emailed_at, &DateTime.utc_now/0)
    end

    update :send_email do
      description "Oban worker action: sends the immediate notification email for this row."
      accept []
      require_atomic? false

      change set_attribute(:emailed_at, &DateTime.utc_now/0)

      change after_action(fn _changeset, notification, context ->
               Emails.deliver_immediate(notification, context)
               {:ok, notification}
             end)
    end

    action :send_digests, OkResult do
      description """
      Scheduled entry point for the daily digest: for every user in
      :daily_digest mode with unemailed, unread rows, sends one digest email
      grouped by kind and stamps every row it covers as emailed.
      """

      run fn _input, context ->
        opts = Varsel.ObanContext.forward(context)

        digest_user_ids =
          User
          |> Ash.Query.filter(
            notification_email_mode == :daily_digest and
              exists(notifications, email_requested and is_nil(emailed_at) and is_nil(read_at))
          )
          |> Ash.Query.select([:id])
          |> Ash.read!(opts)
          |> Enum.map(& &1.id)

        errors =
          Enum.flat_map(digest_user_ids, fn user_id ->
            pending =
              __MODULE__
              |> Ash.Query.filter(
                user_id == ^user_id and email_requested and is_nil(emailed_at) and
                  is_nil(read_at)
              )
              |> Ash.read!(opts)

            Emails.deliver_digest(user_id, pending, context)

            bulk_opts = Keyword.merge(opts, notify?: true, return_errors?: true)

            case Ash.bulk_update(pending, :mark_emailed, %{}, bulk_opts) do
              %Ash.BulkResult{status: :success} -> []
              %Ash.BulkResult{errors: errors} -> errors
            end
          end)

        if errors == [] do
          {:ok, :ok}
        else
          raise "Failed to send notification digests: #{inspect(errors)}"
        end
      end
    end
  end

  policies do
    # The worker re-check reads with no actor; as a plain policy the ownership
    # filter below would narrow it to `user_id == nil`.
    bypass action_type(:read) do
      access_type :strict
      authorize_if AshObanInteraction
    end

    policy action_type(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    policy action_type(:read) do
      authorize_if expr(user_id == ^actor(:id))
    end

    policy action([:mark_read, :mark_unread, :mark_case_read, :mark_kind_read]) do
      authorize_if expr(user_id == ^actor(:id))
    end

    policy action([:record, :mark_emailed, :send_email, :send_digests]) do
      access_type :strict
      authorize_if AshObanInteraction
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "notification"

    publish_all :create, [[:user_id]]
    publish_all :update, [[:user_id]]
  end

  attributes do
    uuid_primary_key :id

    attribute :kind, Kind do
      description "The event kind this notification was raised for."
      allow_nil? false
      public? true
    end

    attribute :count, :integer do
      description "How many events have absorbed into this row while it stayed unread."
      allow_nil? false
      default 1
      public? true
    end

    attribute :last_event_at, :utc_datetime_usec do
      description "When the most recent absorbed event happened."
      allow_nil? false
      public? true
    end

    attribute :read_at, :utc_datetime_usec do
      description "When the user marked this notification read; nil while unread."
      public? true
    end

    attribute :emailed_at, :utc_datetime_usec do
      description "When the notification email for this row was sent; nil until then."
      public? true
    end

    attribute :email_requested, :boolean do
      description "Whether the recipient's preferences ask for an email for this row, as of the latest absorbed event."
      allow_nil? false
      default false
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :user, User do
      description "Who this notification is for."
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :case, Case do
      description "The case this notification is about, if any."
      allow_nil? true
      public? true
      attribute_writable? true
    end

    belongs_to :vulnerability_report, VulnerabilityReport do
      description "The vulnerability report this notification is about, if any."
      allow_nil? true
      public? true
      attribute_writable? true
    end
  end

  identities do
    # The partial index (unread rows only) is what keeps a read row from
    # being reopened by a later event.
    identity :unread_per_subject, [:user_id, :kind, :case_id, :vulnerability_report_id],
      where: expr(is_nil(read_at)),
      nils_distinct?: false
  end
end
