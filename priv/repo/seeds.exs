# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# In dev it seeds a case for each published CVE record in priv/repo/seeds/cves
# (copies of records from cna.erlef.org), spread over the pipeline lanes, so
# the pipeline, CVE pages, search and OSV feed have real data. Each case takes
# the record's affected products, except the two reports, which stay without
# one. Reseeding leaves existing cases where they are and gives one its
# record's packages and Hex channels where it lacks them. It also re-dates
# every seeded case: opened between a day and four months ago, some of them
# left untouched long enough to be stale.
#
# It also gives the mock POC (the "POC" entry under MOCK SIGN IN) two unread
# notifications of every kind, spread over the first two adopted cases.
# Reseeding replaces the mock POC's notifications on those two cases.

defmodule Seeds do
  @moduledoc false

  import Ecto.Query

  alias Varsel.Accounts.User
  alias Varsel.Cases.Case.Import
  alias Varsel.Notifications.Kind
  alias Varsel.Repo

  @cves_dir Path.join(__DIR__, "seeds/cves")

  # A case is not given a CVE ID before it is accepted, so the submitted and
  # triaged ones are reports filed from the record's text, without the record.
  #
  # Each entry is {record, state, days since the case was opened, days since
  # it was last touched}. The ages spread the way a real backlog does: fresh
  # intake, cases a few weeks in, and some past 90 days, with a few left
  # untouched long enough to read as stale in their lane.
  @cases [
    {"CVE-2026-71397", :submitted, 1, 1},
    {"CVE-2026-113431", :triage, 5, 3},
    {"CVE-2026-119446", :draft, 124, 37},
    {"CVE-2026-120286", :draft, 96, 19},
    {"CVE-2026-120730", :draft, 41, 6},
    {"CVE-2026-120997", :draft, 16, 2},
    {"CVE-2026-120999", :draft, 3, 0},
    {"CVE-2026-119613", :review, 63, 8},
    {"CVE-2026-120295", :review, 22, 1},
    {"CVE-2026-115701", :approved, 103, 4}
  ]

  def run do
    poc = mock_user("poc")
    reporter = mock_user("none")
    cases = Enum.map(@cases, &seed_cve(&1, poc, reporter))
    IO.puts("Seeded #{length(@cases)} cases from published CVE records.")

    cases |> Enum.filter(&match?({:adopted, _kase}, &1)) |> Enum.take(2) |> notifications(poc)
  end

  defp seed_cve({cve_id, state, opened_days, touched_days}, poc, reporter) do
    cve_json = @cves_dir |> Path.join("#{cve_id}.json") |> File.read!() |> JSON.decode!()

    seeded =
      if state in [:submitted, :triage] do
        report(cve_json, state, poc, reporter)
      else
        adopt(cve_json, state, poc)
      end

    backdate(seeded, opened_days, touched_days)
    seeded
  end

  # Runs last and on every reseed, so the ages stay relative to today.
  defp backdate({_kind, nil}, _opened_days, _touched_days), do: :ok

  defp backdate({_kind, kase}, opened_days, touched_days) do
    now = DateTime.utc_now()

    Ash.Seed.update!(kase, %{
      inserted_at: DateTime.shift(now, hour: -(opened_days * 24 + 5)),
      updated_at: DateTime.shift(now, hour: -(touched_days * 24 + 2))
    })
  end

  defp report(cve_json, state, poc, reporter) do
    %{title: title, description_md: body} = Import.case_params(cve_json)

    if not Repo.exists?(from(c in "cases", where: c.title == ^title)) do
      %{summary: title, report_body: body, confirms_criteria: true, confirms_in_scope: true}
      |> Varsel.Cases.submit_vulnerability_report!(actor: reporter)
      |> advance(state, poc)
    end

    {:reported, [actor: poc, query: [filter: [title: title]]] |> Varsel.Cases.list_cases!() |> List.first()}
  end

  # :import emits cve_record_published, whose OsvRecord listeners derive the
  # OSV documents in an Oban job. Adoption fills the case from the record,
  # minus the affected packages (see Varsel.Cases.Case.Import).
  defp adopt(cve_json, state, poc) do
    record =
      %{cve_json: cve_json}
      |> Varsel.CVE.import_cve_record!(actor: poc)
      |> Ash.load!(:case, actor: poc)

    kase =
      case record.case do
        nil ->
          %{cve_record_id: record.id}
          |> Varsel.Cases.adopt_cve_record!(actor: poc)
          |> add_packages(cve_json, poc)
          |> advance(state, poc)

        kase ->
          add_packages(kase, cve_json, poc)
      end

    {:adopted, kase}
  end

  # A record lists one `affected` entry per distribution channel; the case
  # holds one package per product. Adding the package gives it its repository
  # channel, and a product the record lists on Hex gets that channel too.
  defp add_packages(kase, cve_json, poc) do
    affected = cve_json["containers"]["cna"]["affected"]

    if packages(kase, poc) == [] do
      affected
      |> Enum.group_by(&{&1["vendor"], &1["product"]})
      |> Enum.each(fn {{vendor, product}, entries} ->
        Varsel.Cases.add_affected_package!(
          %{
            case_id: kase.id,
            vendor: vendor,
            product: product,
            repo_url: Enum.find_value(entries, & &1["repo"])
          },
          actor: poc
        )
      end)
    end

    for package <- packages(kase, poc),
        %{"packageURL" => "pkg:hex/" <> name, "product" => product} <- affected,
        product == package.product,
        "pkg:hex/#{name}" not in Enum.map(package.channels, & &1.purl) do
      Varsel.Cases.add_package_channel!(
        %{
          case_id: kase.id,
          affected_package_id: package.id,
          kind: :package,
          purl_type: "hex",
          name: name
        },
        actor: poc
      )
    end

    kase
  end

  defp packages(kase, poc) do
    Varsel.Cases.list_affected_packages!(
      actor: poc,
      query: [filter: [case_id: kase.id]],
      load: [channels: [:purl]]
    )
  end

  defp advance(kase, state, _poc) when state in [:submitted, :draft], do: kase
  defp advance(kase, :triage, poc), do: Varsel.Cases.triage_case!(kase, actor: poc)
  defp advance(kase, :review, poc), do: Varsel.Cases.request_case_review!(kase, actor: poc)

  defp advance(kase, :approved, poc) do
    kase |> advance(:review, poc) |> Varsel.Cases.approve_case!(actor: poc)
  end

  defp notifications(adopted, poc) do
    cases = Enum.map(adopted, fn {:adopted, kase} -> kase end)
    case_ids = Enum.map(cases, &Ecto.UUID.dump!(&1.id))

    Repo.delete_all(
      from(n in "notifications",
        where: n.user_id == ^Ecto.UUID.dump!(poc.id) and n.case_id in ^case_ids
      )
    )

    for kind <- Kind.values(), kase <- cases do
      Varsel.Notifications.record_notification!(
        %{kind: kind, user_id: poc.id, case_id: kase.id, email_requested: false},
        authorize?: false
      )
    end

    IO.puts("Seeded #{length(Kind.values()) * length(cases)} notifications for the mock POC.")
  end

  # The same upsert the mock sign-in performs (Varsel.Accounts.Strategy.Mock),
  # so signing in under MOCK SIGN IN lands on exactly this user.
  defp mock_user(uid) do
    {^uid, label, role} = List.keyfind(Varsel.Accounts.Strategy.Mock.roles(), uid, 0)

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
end

if Mix.env() == :dev do
  Seeds.run()
end
