# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.ProposeActions do
  @moduledoc """
  The specialized, strongly-typed `propose_*` create actions of
  `Varsel.Cases.Proposal`, split into a Spark DSL fragment to keep the main
  resource focused on the core proposal lifecycle (reads, the private generic
  `:propose`, accept/decline/withdraw, policies, storage).

  Each action declares only the payload of one target/operation;
  `Varsel.Cases.Proposal.Changes.PackProposal` folds its typed arguments into
  the generic proposal shape. The shared author change and the
  CaseState / ValidTarget validations live on the parent resource's
  `changes`/`validations` blocks (`on: [:create]`), so they apply here too and
  nothing is repeated per action. These actions are the public MCP/GraphQL
  surface; the generic `:propose` stays private.
  """

  use Spark.Dsl.Fragment, of: Ash.Resource

  alias Varsel.Cases.AffectedPackage.ProgramFile
  alias Varsel.Cases.PackageChannel.ChannelInput
  alias Varsel.Cases.Proposal.Changes.PackProposal
  alias Varsel.Cases.VersionEvent.EventInput

  actions do
    create :propose_credit do
      description """
      Proposes adding a credit (contributor) to the case.

      Give the person's provider handles when known: an accepted credit is
      linked to the account holding one, takes the name and organization that
      account asked to be credited as where the proposal leaves them blank,
      and a handle is confirmed at its provider on acceptance.
      """

      accept [:case_id, :reasoning]
      argument :name, :string, allow_nil?: false
      argument :credit_type, Varsel.Cases.CaseCredit.CreditType, allow_nil?: false
      argument :organization, :string

      argument :handles, {:array, Varsel.Cases.CaseCredit.Handle} do
        description "The provider accounts the person goes by, as {strategy, username}."
      end

      change {PackProposal, target: :credit, operation: :insert}
    end

    create :propose_description do
      description """
      Proposes setting the case description (markdown) — what the vulnerability IS.

      Do not list the affected versions: the published record appends them
      automatically from the case's affected packages.
      """

      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :description_md}
    end

    create :propose_title do
      description "Proposes setting the case title."
      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :title}
    end

    create :propose_workarounds do
      description """
      Proposes setting the case workarounds (markdown). The section is
      optional: pass an explicit null value to propose removing it.
      """

      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :workarounds_md}
    end

    create :propose_configurations do
      description """
      Proposes setting the affected configurations (markdown). The section is
      optional: pass an explicit null value to propose removing it.
      """

      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :configurations_md}
    end

    create :propose_solutions do
      description """
      Proposes setting the case solutions (markdown). The section is optional:
      pass an explicit null value to propose removing it.
      """

      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :solutions_md}
    end

    create :propose_technical_analysis do
      description """
      Proposes setting the case's technical analysis (markdown): how the
      vulnerability works, step by step. Published as
      containers.cna.x_technicalAnalysis. The section is optional: pass an
      explicit null value to propose removing it.
      """

      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :technical_analysis_md}
    end

    create :propose_proof_of_concept do
      description """
      Proposes setting the case's proof of concept (markdown): the minimum
      steps that reproduce the issue. Published as
      containers.cna.x_proofOfConcept. The section is optional: pass an
      explicit null value to propose removing it.
      """

      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :proof_of_concept_md}
    end

    create :propose_internal_notes do
      description """
      Proposes setting the case's internal working notes (markdown). These are
      for the case team only and are never rendered into the published record,
      so keep anything that belongs in the advisory in the real fields. Pass an
      explicit null value to propose clearing them.
      """

      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :internal_notes}
    end

    create :propose_discovery do
      description "Proposes setting how the vulnerability was discovered."
      accept [:case_id, :reasoning]
      argument :value, Varsel.Cases.Case.Discovery, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :discovery}
    end

    create :propose_cvss do
      description """
      Proposes setting the CVSS v4.0 vector (a CVSS:4.0/... string). Pass an
      explicit null value to propose removing the score.
      """

      accept [:case_id, :reasoning]
      # Typed as CVSS so the vector is fully validated at the argument layer.
      argument :value, Varsel.Types.CVSS, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :cvss_v4}

      # PackProposal packs the dumped {vector, score, severity, version} map;
      # store just the vector string so the proposal envelope stays the plain
      # CVSS text (score/severity/version are derived on re-cast anyway).
      change fn changeset, _context ->
        Ash.Changeset.update_change(changeset, :proposed_value, fn
          %{"value" => nil} -> %{"value" => nil}
          %{"value" => dumped} -> %{"value" => dumped["vector"]}
        end)
      end
    end

    create :propose_date_public do
      description """
      Proposes setting the public disclosure date. Pass an explicit null value
      to propose removing it.
      """

      accept [:case_id, :reasoning]
      argument :value, :utc_datetime, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :date_public}
    end

    create :propose_timeline do
      description "Proposes setting the disclosure timeline entries."
      accept [:case_id, :reasoning]
      argument :value, {:array, Varsel.Cases.Case.TimelineEntry}, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :timeline}
    end

    create :propose_cna_override do
      description """
      Proposes setting the raw CNA container override map. Pass an explicit
      null value to propose dropping the override.
      """

      accept [:case_id, :reasoning]
      argument :value, :map, allow_nil?: true
      change {PackProposal, target: :case, operation: :set, field: :cna_override}
    end

    create :propose_weakness do
      description "Proposes adding a CWE weakness to the case."
      accept [:case_id, :reasoning]
      argument :cwe_id, :integer, allow_nil?: false
      change {PackProposal, target: :weakness, operation: :insert}
    end

    create :propose_impact do
      description """
      Proposes adding a CAPEC attack-pattern impact to the case, optionally
      with a markdown description of the impact scenario: what an attacker
      gains and who is affected in practice. Leave out version ranges and
      the CVSS score; they are carried by other fields.
      """

      accept [:case_id, :reasoning]
      argument :capec_id, :integer, allow_nil?: false
      argument :description_md, :string
      change {PackProposal, target: :impact, operation: :insert}
    end

    create :propose_impact_description do
      description """
      Proposes setting the markdown description of an impact that is already
      on the case (target_id). Pass an explicit null value to propose
      removing it, which puts the CAPEC catalog name back in its place.
      """

      accept [:case_id, :target_id, :reasoning]
      argument :value, :string, allow_nil?: true
      change {PackProposal, target: :impact, operation: :set, field: :description_md}
    end

    create :propose_reference do
      description """
      Proposes adding a reference URL to the case. Tags are e.g.
      ["vendor-advisory"], ["patch"], ["x_version-scheme"]. Do NOT propose the
      cna.erlef.org/cves/... or osv.dev/... references, nor the introducing
      and fix commits -- Varsel adds those automatically.
      """

      accept [:case_id, :reasoning]
      argument :url, :string, allow_nil?: false

      argument :name, :string do
        description "What the link is shown as, often the page's title."
      end

      argument :tags, {:array, :string}
      change {PackProposal, target: :reference, operation: :insert}
    end

    create :propose_affected_package do
      description """
      Proposes adding an affected package to the case, together with its
      distribution channels and version boundary facts in one proposal —
      accepting it creates the package and all its children at once. This is the
      normal way to add a product; reach for propose_package_channel /
      propose_version_event only to extend a package that is already accepted.

      In channels, list the distribution channels only — the source repo's
      pkg:github channel is derived from repo_url, so you normally don't add it
      (do so only for something like a second forge host).

      version_events are package-global boundaries. When channels genuinely need
      different versions from each other, don't try to express it here — stop
      and involve a human.
      """

      accept [:case_id, :reasoning]
      argument :vendor, :string, allow_nil?: false
      argument :product, :string, allow_nil?: false
      argument :repo_url, :string
      argument :cpe, :string
      argument :program_files, {:array, ProgramFile}
      argument :platforms, {:array, :string}
      argument :allow_unreleased_fix, :boolean
      argument :allow_unreleased_intro, :boolean
      argument :channels, {:array, ChannelInput}
      argument :version_events, {:array, EventInput}
      change {PackProposal, target: :affected_package, operation: :insert}
    end

    create :propose_otp_affected_package do
      description """
      Proposes adding an Erlang/OTP affected package (preset) to the case: one
      pkg:otp/<application> channel per listed application plus a version
      boundary fact per commit, with vendor/product/repo/CPE prefilled. Paths in
      program_files are repository-root-relative. When vulnerable code moved
      between OTP applications over time, additionally propose channel-scoped
      version events bounding the former application's channel.
      """

      accept [:case_id, :reasoning]
      argument :applications, {:array, :string}, allow_nil?: false
      argument :introduced_commit, :string
      argument :fixed_commits, {:array, :string}
      argument :program_files, {:array, ProgramFile}
      change {PackProposal, target: :affected_package, operation: :insert, preset: :otp}
    end

    create :propose_elixir_affected_package do
      description "Proposes adding an Elixir affected package (preset) to the case."
      accept [:case_id, :reasoning]
      argument :applications, {:array, :string}, allow_nil?: false
      argument :introduced_commit, :string
      argument :fixed_commits, {:array, :string}
      argument :program_files, {:array, ProgramFile}
      change {PackProposal, target: :affected_package, operation: :insert, preset: :elixir}
    end

    create :propose_gleam_affected_package do
      description "Proposes adding a Gleam affected package (preset) to the case."
      accept [:case_id, :reasoning]
      argument :introduced_commit, :string
      argument :fixed_commits, {:array, :string}
      argument :program_files, {:array, ProgramFile}
      change {PackProposal, target: :affected_package, operation: :insert, preset: :gleam}
    end

    create :propose_package_channel do
      description """
      Proposes adding a distribution channel to an affected package that is
      already accepted (target_id); for a new package, author its channels
      inline on propose_affected_package instead. The source repository's own
      channel is derived from the package's repo_url — normally you don't add
      it here (do so only for something like a second forge host).
      """

      accept [:case_id, :target_id, :reasoning]
      argument :kind, Varsel.Cases.PackageChannel.Kind
      argument :purl_type, Varsel.Cases.PackageChannel.PurlType
      argument :namespace, :string
      argument :name, :string
      argument :domain, :string
      argument :qualifiers, :map
      argument :subpath, :string
      argument :version_type, Varsel.Cases.PackageChannel.VersionType
      argument :tag_prefix, :string
      argument :tag_suffixes, {:array, :string}
      argument :versions_override, {:array, :map}
      argument :entry_override, :map
      change {PackProposal, target: :package_channel, operation: :insert}
    end

    create :propose_version_event do
      description """
      Proposes adding a version boundary event under an affected package
      (target_id). package_channel_id scopes the boundary to one channel of
      that package — a date boundary on a service channel, or a channel whose
      versions genuinely differ from the repo derivation.
      """

      accept [:case_id, :target_id, :reasoning]
      argument :event, Varsel.Cases.VersionEvent.Event, allow_nil?: false
      argument :commit_sha, :string
      argument :version, :string
      argument :package_channel_id, :uuid
      argument :note, :string
      change {PackProposal, target: :version_event, operation: :insert}
    end

    create :propose_delete do
      description "Proposes removing a child row (addressed by target/target_id)."
      accept [:case_id, :target, :target_id, :reasoning]
      change {PackProposal, operation: :delete}
    end
  end
end
