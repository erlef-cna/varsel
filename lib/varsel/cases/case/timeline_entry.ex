# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.TimelineEntry do
  @moduledoc """
  Embedded timeline event, rendered as one `timeline[]` entry in the CNA
  container (`{time, lang, value}`). Rare in practice, so the whole timeline
  is a single embedded array on the case rather than a child table.
  """

  use Ash.Resource,
    data_layer: :embedded,
    extensions: [AshGraphql.Resource]

  graphql do
    type :case_timeline_entry
  end

  attributes do
    attribute :time, :utc_datetime do
      description "When the event happened."
      allow_nil? false
      public? true
    end

    attribute :value_md, :string do
      description "Markdown description of the event; rendered to plain text."
      allow_nil? false
      public? true
    end
  end
end
