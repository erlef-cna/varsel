# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Stages the fictional in-progress case the documentation screenshots show:
# the mock users in every role, a draft case with affected package, boundary
# facts, cached derivation, open and resolved proposals, comments, an invite,
# a second case in review, and a submitted vulnerability report.
#
#     mix run priv/repo/dev_seeds/docs_screenshots.exs
#
# Idempotent: reseeding replaces everything it created (marker:
# docs-screenshots-seed). Dev database only; see priv/repo/dev_seeds/README.md
# for the full screenshot workflow.

import Ecto.Query

alias Varsel.Accounts.User
alias Varsel.CAPEC.AttackPattern
alias Varsel.CWE.Weakness
alias Varsel.Repo

defmodule DevSeed.DocsScreenshots do
  @moduledoc false

  require Ash.Query

  @marker "docs-screenshots-seed"
  @cve_id "CVE-2026-909090"
  @report_summary "Forged webhook events accepted by webhook_relay when the signature header is empty"
  @intro_sha "3f7c2a91d4b8e6f0a1c5d9e8b7a6f5c4d3e2b1a0"
  @fix_sha "9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"

  @description """
  Improper Verification of Cryptographic Signature vulnerability in acme \
  webhook_relay allows an unauthenticated remote attacker to submit forged \
  webhook events via an empty `x-relay-signature` header.

  `WebhookRelay.Verifier.verify/2` in `lib/webhook_relay/verifier.ex` treats \
  a missing or empty signature header as a legacy pass-through, so any \
  request whose header is blank reaches the configured handlers unverified.\
  """

  def run do
    wipe()

    poc = mock_user("poc", :poc)
    supporter = mock_user("supporter", :supporter)
    collaborator = mock_user("none", nil)

    kase = seed_main_case(poc, supporter, collaborator)
    review_case = seed_review_case(supporter)
    seed_report(collaborator)

    # Contract with docs_screenshots_capture.mjs: where to find the case ids.
    manifest = Path.join(__DIR__, ".docs_screenshots_manifest.json")
    File.write!(manifest, Jason.encode!(%{main_case_id: kase.id, review_case_id: review_case.id}))

    IO.puts("Seeded docs screenshot data: main case #{kase.id} (#{@cve_id}).")
    IO.puts("Manifest for the capture script: #{manifest}")
  end

  # ── wipe ──────────────────────────────────────────────────────────────────

  defp wipe do
    report_ids =
      Repo.all(from(r in "vulnerability_reports", where: r.summary == ^@report_summary, select: r.id))

    Repo.delete_all(from(v in "vulnerability_reports_versions", where: v.version_source_id in ^report_ids))

    Repo.delete_all(from(r in "vulnerability_reports", where: r.id in ^report_ids))

    Repo.delete_all(from(c in "cases", where: like(c.internal_notes, ^"%#{@marker}%")))

    record_ids =
      Repo.all(
        from(r in "cve_records",
          where:
            fragment(
              "coalesce(cve_json->'cveMetadata'->>'cveId', reservation_json->>'cve_id') = ?",
              ^@cve_id
            ),
          select: r.id
        )
      )

    Repo.delete_all(from(v in "cve_records_versions", where: v.version_source_id in ^record_ids))
    Repo.delete_all(from(r in "cve_records", where: r.id in ^record_ids))

    # The case-side paper trails carry no FK, so sweep the orphans they leave.
    for {versions, source} <- [
          {"cases_versions", "cases"},
          {"case_proposals_versions", "case_proposals"},
          {"case_assignments_versions", "case_assignments"},
          {"case_invites_versions", "case_invites"},
          {"case_comments_versions", "case_comments"},
          {"case_affected_packages_versions", "case_affected_packages"},
          {"case_package_channels_versions", "case_package_channels"},
          {"case_version_events_versions", "case_version_events"},
          {"case_references_versions", "case_references"},
          {"case_credits_versions", "case_credits"},
          {"case_weaknesses_versions", "case_weaknesses"},
          {"case_impacts_versions", "case_impacts"}
        ] do
      Repo.query!(
        "DELETE FROM #{versions} WHERE NOT EXISTS " <>
          "(SELECT 1 FROM #{source} s WHERE s.id = #{versions}.version_source_id)"
      )
    end
  end

  # ── users ─────────────────────────────────────────────────────────────────

  # The same upsert the mock sign-in performs, so signing in as a role in the
  # browser lands on exactly the user seeded here.
  defp mock_user(uid, role) do
    label =
      Enum.find_value(Varsel.Accounts.Strategy.Mock.roles(), uid, fn {u, l, _} ->
        if u == uid, do: l
      end)

    Ash.create!(
      User,
      %{
        user_info: %{
          "sub" => uid,
          "preferred_username" => "mock-#{uid}",
          "name" => "Mock #{label}",
          "email" => "mock-#{uid}@example.com"
        },
        oauth_tokens: %{},
        role: role
      },
      action: :register_with_mock,
      authorize?: false
    )
  end

  # ── the main case ─────────────────────────────────────────────────────────

  defp seed_main_case(poc, supporter, collaborator) do
    kase =
      Varsel.Cases.open_case!(
        %{
          title: "Webhook signature bypass via empty signature header in webhook_relay",
          description_md: @description,
          cvss_v4: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
          discovery: :external,
          internal_notes: """
          Trusted report (reproduced by the reporter, fix verified against \
          2.0.3). Intro boundary confirmed by pickaxe on the pass-through \
          clause.

          Seeded by priv/repo/dev_seeds/docs_screenshots.exs \
          (#{@marker}); safe to delete.\
          """
        },
        actor: supporter
      )

    record =
      Ash.create!(
        Varsel.CVE.CveRecord,
        %{
          reservation_json: %{
            "cve_id" => @cve_id,
            "cve_year" => "2026",
            "owning_cna" => "EEF",
            "reserved" => "2026-01-01T00:00:00.000Z",
            "state" => "RESERVED"
          }
        },
        action: :reserve,
        authorize?: false
      )

    kase = Varsel.Cases.assign_case_cve_id!(kase, %{cve_record_id: record.id}, actor: poc)

    package =
      Varsel.Cases.add_affected_package!(
        %{
          case_id: kase.id,
          vendor: "acme",
          product: "webhook_relay",
          repo_url: "https://github.com/acme/webhook_relay",
          program_files: [
            %{
              path: "lib/webhook_relay/verifier.ex",
              modules: ["'Elixir.WebhookRelay.Verifier'"],
              routines: ["'Elixir.WebhookRelay.Verifier':verify/2"]
            }
          ]
        },
        actor: supporter
      )

    hex_channel =
      Varsel.Cases.add_package_channel!(
        %{
          case_id: kase.id,
          affected_package_id: package.id,
          kind: :package,
          purl_type: :hex,
          name: "webhook_relay"
        },
        actor: supporter
      )

    # Adding the package already created its repository channel from repo_url.
    github_channel =
      Varsel.Cases.PackageChannel
      |> Ash.Query.filter(affected_package_id == ^package.id and purl_type == :github)
      |> Ash.read_one!(authorize?: false)

    Varsel.Cases.add_version_event!(
      %{
        case_id: kase.id,
        affected_package_id: package.id,
        event: :introduced,
        commit_sha: @intro_sha
      },
      actor: supporter
    )

    Varsel.Cases.add_version_event!(
      %{case_id: kase.id, affected_package_id: package.id, event: :fixed, commit_sha: @fix_sha},
      actor: supporter
    )

    # A hand-built cache in place of a real refresh: the fictional repository
    # has nothing to clone, and the stamp lands after the facts above, so the
    # workspace renders the ranges without a staleness flag.
    Varsel.Cases.store_affected_package_derivation!(
      package,
      %{
        derivation_cache: %{
          "channels" => %{
            hex_channel.id => %{
              "versions" => [
                %{
                  "version" => "1.2.0",
                  "lessThan" => "2.0.3",
                  "status" => "affected",
                  "versionType" => "semver"
                }
              ],
              "pending" => [],
              "issues" => []
            },
            github_channel.id => %{
              "versions" => [
                %{
                  "version" => @intro_sha,
                  "lessThan" => @fix_sha,
                  "status" => "affected",
                  "versionType" => "git"
                }
              ],
              "pending" => [],
              "issues" => []
            }
          },
          "cpe_matches" => [
            %{"versionStartIncluding" => "1.2.0", "versionEndExcluding" => "2.0.3"}
          ],
          "call_outs" => [],
          "issues" => []
        }
      },
      authorize?: false
    )

    ensure_catalog_rows()

    Varsel.Cases.add_case_weakness!(%{case_id: kase.id, cwe_id: 347}, actor: supporter)
    Varsel.Cases.add_case_impact!(%{case_id: kase.id, capec_id: 475}, actor: supporter)

    Varsel.Cases.add_case_reference!(
      %{
        case_id: kase.id,
        url: "https://github.com/acme/webhook_relay/security/advisories/GHSA-docs-seed-demo",
        tags: ["vendor-advisory", "related"]
      },
      actor: supporter
    )

    Varsel.Cases.add_case_reference!(
      %{
        case_id: kase.id,
        url: "https://github.com/acme/webhook_relay/commit/#{@fix_sha}",
        tags: ["patch"]
      },
      actor: supporter
    )

    Varsel.Cases.add_case_credit!(
      %{case_id: kase.id, name: "Riley Sandoval", credit_type: :finder},
      actor: supporter
    )

    # The maintainer follows the case: assigned by the POC, comments, and
    # proposes; one proposal already accepted, two still open for the shots.
    Varsel.Cases.assign_case_user!(%{case_id: kase.id, user_id: collaborator.id}, actor: poc)

    # Granting access verifies the handle against the real provider, so the
    # invite goes to GitHub's demo account. Offline, the seed just skips it.
    case Varsel.Cases.grant_case_access(kase, :github, "octocat", actor: supporter) do
      {:ok, _kase} ->
        :ok

      {:error, error} ->
        IO.puts("Skipped the octocat invite (GitHub lookup failed): #{Exception.message(error)}")
    end

    accepted =
      Varsel.Cases.propose_credit!(
        %{
          case_id: kase.id,
          name: "Noa Lindqvist",
          credit_type: :remediation_developer,
          reasoning: "Wrote and released the 2.0.3 fix."
        },
        actor: collaborator
      )

    Varsel.Cases.accept_case_proposal!(accepted, actor: poc)

    Varsel.Cases.propose_workarounds!(
      %{
        case_id: kase.id,
        value:
          "Reject requests carrying an empty `x-relay-signature` header at the reverse proxy " <>
            "until the upgrade lands. Verified against 1.9.4: forged events are refused.",
        reasoning: "Tested the header filter against a vulnerable version; forged events no longer reach the handlers."
      },
      actor: collaborator
    )

    Varsel.Cases.propose_description!(
      %{
        case_id: kase.id,
        value:
          String.replace(
            @description,
            "a legacy pass-through",
            "a pass-through kept for pre-2.0 senders"
          ),
        reasoning: "Names why the pass-through exists; the fix removes exactly this clause."
      },
      actor: collaborator
    )

    Varsel.Cases.post_case_comment!(
      %{
        case_id: kase.id,
        body: "Release is scheduled for Thursday. The advisory draft is ready on the repo, GHSA-docs-seed-demo."
      },
      actor: collaborator
    )

    Varsel.Cases.post_case_comment!(
      %{
        case_id: kase.id,
        body:
          "Derived ranges match the advisory. Waiting on the workaround proposal review, then this is ready for review."
      },
      actor: supporter
    )

    kase
  end

  # The CWE/CAPEC catalogs sync weekly from MITRE; a fresh dev database may
  # not hold them yet, and the two rows the case classifies under are all the
  # workspace needs to render names instead of bare IDs.
  defp ensure_catalog_rows do
    if !match?({:ok, _}, Ash.get(Weakness, %{cwe_id: 347}, authorize?: false)) do
      Ash.Seed.seed!(Weakness, %{
        cwe_id: 347,
        name: "Improper Verification of Cryptographic Signature",
        abstraction: :base,
        status: :stable,
        description: "The product does not verify, or incorrectly verifies, the cryptographic signature for data."
      })
    end

    if !match?(
         {:ok, _},
         Ash.get(AttackPattern, %{capec_id: 475}, authorize?: false)
       ) do
      Ash.Seed.seed!(AttackPattern, %{
        capec_id: 475,
        name: "Signature Spoofing by Improper Validation",
        abstraction: :detailed,
        status: :stable,
        description: "An attacker exploits improper validation of signatures to forge data provenance."
      })
    end
  end

  # ── a second case, in review, so the board shows both lanes ──────────────

  defp seed_review_case(supporter) do
    kase =
      Varsel.Cases.open_case!(
        %{
          title: "Atom exhaustion via crafted node names in cluster_beacon",
          description_md:
            "Allocation of Resources Without Limits or Throttling vulnerability in acme " <>
              "cluster_beacon allows a remote attacker on the cluster network to exhaust the " <>
              "atom table via crafted node announcement frames.",
          cvss_v4: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
          discovery: :external,
          internal_notes: """
          Awaiting POC review.

          Seeded by priv/repo/dev_seeds/docs_screenshots.exs \
          (#{@marker}); safe to delete.\
          """
        },
        actor: supporter
      )

    Varsel.Cases.request_case_review!(kase, actor: supporter)
  end

  # ── an untriaged report for the POC queue ─────────────────────────────────

  defp seed_report(reporter) do
    Varsel.CVE.submit_vulnerability_report!(
      %{
        summary: @report_summary,
        report_body: """
        webhook_relay accepts any event when the x-relay-signature header is present but \
        empty. Verifier.verify/2 returns :ok on `""` before comparing digests. Reproduced \
        on 1.9.4 with a plain curl against a default mount; forged payloads reach the \
        handler. 2.0.3 refuses the same request.\
        """,
        confirms_criteria: true,
        confirms_in_scope: true
      },
      actor: reporter
    )
  end
end

if Mix.env() != :dev do
  raise "docs_screenshots.exs seeds the dev database only (MIX_ENV=#{Mix.env()})"
end

DevSeed.DocsScreenshots.run()
