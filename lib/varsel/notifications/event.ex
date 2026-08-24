# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Event do
  @moduledoc """
  One outbox row per raised event, written after a source action's
  transaction commits (`Varsel.Notifications.Notifier`) and fanned out to
  `Varsel.Notifications.Notification` rows by one Oban worker.

  `:emit` is reached only as `Varsel.Service.notifier/0`; no
  other actor may create one. `:fan_out` runs only under the AshOban bypass.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Notifications,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban]

  alias AshOban.Checks.AshObanInteraction
  alias Varsel.Accounts.User
  alias Varsel.Cases.Case
  alias Varsel.CVE.VulnerabilityReport
  alias Varsel.Notifications.Event.Changes.FanOut
  alias Varsel.Notifications.Event.Validations.ExactlyOneSubject
  alias Varsel.Notifications.Event.Validations.RecipientMatchesAudience
  alias Varsel.Notifications.Kind

  postgres do
    table "notification_events"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :vulnerability_report, on_delete: :delete
      reference :actor, on_delete: :nilify
      reference :recipient, on_delete: :delete
    end
  end

  oban do
    triggers do
      trigger :fan_out do
        action :fan_out
        where expr(is_nil(processed_at))
        worker_module_name Varsel.Notifications.Event.FanOutWorker
        scheduler_module_name Varsel.Notifications.Event.FanOutScheduler
        queue :default
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
        # Ash.Actions.Read.Relationships carries only context[:shared] into a
        # related query, not context[:private].
        shared_context [:ash_oban?]
      end
    end
  end

  actions do
    create :emit do
      description "Records one raised event. Reached only as Varsel.Service.notifier/0."
      primary? true
      accept [:kind, :case_id, :vulnerability_report_id, :actor_id, :recipient_id]

      change run_oban_trigger(:fan_out)
    end

    read :read do
      description "Plain read; used by the Oban trigger scheduler/worker."
      primary? true
      pagination keyset?: true, required?: false
    end

    update :fan_out do
      description "Oban worker action: records a notification for each recipient in this event's audience."
      accept []
      require_atomic? false

      change set_attribute(:processed_at, &DateTime.utc_now/0)
      change FanOut
    end
  end

  policies do
    policy action(:emit) do
      access_type :strict
      authorize_if actor_attribute_equals(:system, :notifier)
    end

    policy action(:fan_out) do
      access_type :strict
      authorize_if AshObanInteraction
    end

    policy action_type(:read) do
      access_type :strict
      authorize_if AshObanInteraction
    end
  end

  validations do
    validate ExactlyOneSubject, on: [:create]
    validate RecipientMatchesAudience, on: [:create]
  end

  attributes do
    uuid_primary_key :id

    attribute :kind, Kind do
      description "The event kind that was raised."
      allow_nil? false
      public? true
    end

    attribute :processed_at, :utc_datetime_usec do
      description "When the fan-out worker recorded notifications for this event; nil until then."
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, Case do
      description "The case this event is about, if any."
      allow_nil? true
      public? true
      attribute_writable? true
    end

    belongs_to :vulnerability_report, VulnerabilityReport do
      description "The vulnerability report this event is about, if any."
      allow_nil? true
      public? true
      attribute_writable? true
    end

    belongs_to :actor, User do
      description "Who raised the event, if anyone. Excluded from its own audience."
      allow_nil? true
      public? true
      attribute_writable? true
    end

    belongs_to :recipient, User do
      description "The single recipient, for kinds whose audience is :recipient."
      allow_nil? true
      public? true
      attribute_writable? true
    end
  end
end
