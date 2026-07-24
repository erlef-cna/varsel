# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.VersionEvent.EventInput do
  @moduledoc """
  A version boundary fact authored inline as part of a
  `propose_affected_package` insert, so the package and its boundary facts are
  one proposal (and one accept).

  These are package-global boundaries only. A boundary that applies to just one
  channel (`package_channel_id`) is not expressible here — the channels have no
  ids at authoring time — and stays a post-acceptance `propose_version_event`;
  when different channels genuinely need different versions, stop and involve a
  human.
  """

  use Ash.Resource,
    data_layer: :embedded,
    extensions: [AshGraphql.Resource]

  alias Varsel.Cases.VersionEvent.Event

  graphql do
    type :case_event_input
  end

  attributes do
    attribute :event, Event do
      description "Which boundary this fact records: :introduced or :fixed."
      allow_nil? false
      public? true
    end

    attribute :commit_sha, :string do
      description "Full 40-character commit SHA of the boundary commit. Varsel resolves it to a version range at render time."
      constraints match: ~r/^[0-9a-f]{40}$/
      public? true
    end

    attribute :version, :string do
      description "Explicit version boundary, for channels where commits don't apply. Use instead of commit_sha, not alongside it."
      public? true
    end

    attribute :note, :string do
      description "Context for reviewers (which release branch, why this boundary)."
      public? true
    end
  end
end
