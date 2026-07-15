# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposable do
  @moduledoc """
  The single registry of which fields on which Cases resources may be the
  subject of a `Varsel.Cases.Proposal`.

  `fields/1` is the proposable payload of a resource: the accept-list of its
  `:add` / `:apply_proposal_insert` actions and the allowed payload keys of an
  `:insert` proposal. `set_fields/1` is the subset targetable by a `:set`
  proposal (empty for pure join rows like weaknesses/impacts, which are only
  ever inserted or deleted).

  Deliberately explicit lists — never resource introspection — so
  state-machine, bookkeeping, and system fields are excluded by construction.
  A test asserts every listed field exists on its resource.
  """

  alias Varsel.Cases.CaseImpact
  alias Varsel.Cases.CaseWeakness
  alias Varsel.Cases.VersionEvent

  @case_fields [
    :title,
    :description_md,
    :workarounds_md,
    :configurations_md,
    :solutions_md,
    :discovery,
    :cvss_v4,
    :date_public,
    :timeline,
    :cna_override
  ]

  @affected_package_fields [
    :vendor,
    :product,
    :repo_url,
    :cpe,
    :default_status,
    :modules,
    :program_files,
    :program_routines,
    :platforms,
    :allow_unreleased_fix,
    :position
  ]

  @package_channel_fields [
    :purl_type,
    :namespace,
    :name,
    :qualifiers,
    :tag_suffixes,
    :versions_override,
    :entry_override,
    :position
  ]

  @version_event_fields [:event, :commit_sha, :version, :note]

  @reference_fields [:url, :tags, :position]

  @credit_fields [:name, :organization, :credit_type, :position]

  @weakness_fields [:cwe_id, :position]

  @impact_fields [:capec_id, :position]

  @doc "Proposable payload fields of a resource (insert payload / edit accept-list)."
  @spec fields(module()) :: [atom()]
  def fields(Varsel.Cases.Case), do: @case_fields
  def fields(Varsel.Cases.AffectedPackage), do: @affected_package_fields
  def fields(Varsel.Cases.PackageChannel), do: @package_channel_fields
  def fields(VersionEvent), do: @version_event_fields
  def fields(Varsel.Cases.CaseReference), do: @reference_fields
  def fields(Varsel.Cases.CaseCredit), do: @credit_fields
  def fields(CaseWeakness), do: @weakness_fields
  def fields(CaseImpact), do: @impact_fields

  @doc "Fields a :set proposal may target. Join rows are insert/delete-only."
  @spec set_fields(module()) :: [atom()]
  def set_fields(CaseWeakness), do: []
  def set_fields(CaseImpact), do: []
  def set_fields(resource), do: fields(resource)

  @doc """
  Extra keys allowed in an :insert proposal payload beyond `fields/1` —
  relationship scoping the payload itself must carry (the parent FK comes
  from the proposal's `target_id` instead).
  """
  @spec insert_extra_fields(module()) :: [atom()]
  def insert_extra_fields(VersionEvent), do: [:package_channel_id]
  def insert_extra_fields(_resource), do: []
end
