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
  alias Varsel.Cases.Proposal.Changes.PackProposal

  actions do
    create :propose_credit do
      description "Proposes adding a credit (contributor) to the case."
      accept [:case_id, :reasoning]
      argument :name, :string, allow_nil?: false
      argument :credit_type, Varsel.Cases.CaseCredit.CreditType, allow_nil?: false
      argument :organization, :string
      change {PackProposal, target: :credit, operation: :insert}
    end

    create :propose_description do
      description "Proposes setting the case description (markdown)."
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
      description "Proposes setting the case workarounds (markdown)."
      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :workarounds_md}
    end

    create :propose_configurations do
      description "Proposes setting the affected configurations (markdown)."
      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :configurations_md}
    end

    create :propose_solutions do
      description "Proposes setting the case solutions (markdown)."
      accept [:case_id, :reasoning]
      argument :value, :string, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :solutions_md}
    end

    create :propose_discovery do
      description "Proposes setting how the vulnerability was discovered."
      accept [:case_id, :reasoning]
      argument :value, Varsel.Cases.Case.Discovery, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :discovery}
    end

    create :propose_cvss do
      description "Proposes setting the CVSS v4.0 vector."
      accept [:case_id, :reasoning]
      argument :value, Varsel.Types.CVSS, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :cvss_v4}
    end

    create :propose_date_public do
      description "Proposes setting the public disclosure date."
      accept [:case_id, :reasoning]
      argument :value, :utc_datetime, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :date_public}
    end

    create :propose_timeline do
      description "Proposes setting the disclosure timeline entries."
      accept [:case_id, :reasoning]
      argument :value, {:array, Varsel.Cases.Case.TimelineEntry}, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :timeline}
    end

    create :propose_cna_override do
      description "Proposes setting the raw CNA container override map."
      accept [:case_id, :reasoning]
      argument :value, :map, allow_nil?: false
      change {PackProposal, target: :case, operation: :set, field: :cna_override}
    end

    create :propose_weakness do
      description "Proposes adding a CWE weakness to the case."
      accept [:case_id, :reasoning]
      argument :cwe_id, :integer, allow_nil?: false
      change {PackProposal, target: :weakness, operation: :insert}
    end

    create :propose_impact do
      description "Proposes adding a CAPEC attack-pattern impact to the case."
      accept [:case_id, :reasoning]
      argument :capec_id, :integer, allow_nil?: false
      change {PackProposal, target: :impact, operation: :insert}
    end

    create :propose_reference do
      description """
      Proposes adding a reference URL to the case. Tags are e.g.
      ["vendor-advisory"], ["patch"], ["x_version-scheme"]. Do NOT propose the
      cna.erlef.org/cves/... or osv.dev/... references -- Varsel adds those
      automatically when the CVE ID is assigned.
      """

      accept [:case_id, :reasoning]
      argument :url, :string, allow_nil?: false
      argument :tags, {:array, :string}
      change {PackProposal, target: :reference, operation: :insert}
    end

    create :propose_affected_package do
      description "Proposes adding an affected package to the case."
      accept [:case_id, :reasoning]
      argument :vendor, :string, allow_nil?: false
      argument :product, :string, allow_nil?: false
      argument :repo_url, :string
      argument :cpe, :string
      argument :default_status, Varsel.Cases.AffectedPackage.DefaultStatus
      argument :program_files, {:array, ProgramFile}
      argument :platforms, {:array, :string}
      argument :allow_unreleased_fix, :boolean
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
      description "Proposes adding a package channel under an affected package (target_id)."
      accept [:case_id, :target_id, :reasoning]
      argument :purl_type, Varsel.Cases.PackageChannel.PurlType, allow_nil?: false
      argument :namespace, :string
      argument :name, :string
      argument :qualifiers, :map
      argument :subpath, :string
      argument :tag_suffixes, {:array, :string}
      argument :versions_override, {:array, :map}
      argument :entry_override, :map
      change {PackProposal, target: :package_channel, operation: :insert}
    end

    create :propose_version_event do
      description "Proposes adding a version boundary event under an affected package (target_id)."
      accept [:case_id, :target_id, :reasoning]
      argument :event, Varsel.Cases.VersionEvent.Event, allow_nil?: false
      argument :commit_sha, :string
      argument :version, :string
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
