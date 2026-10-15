# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.UserInstallationTest do
  use Varsel.DataCase, async: true

  import Varsel.Fixtures

  alias Ash.Error.Forbidden
  alias Varsel.GitHub
  alias Varsel.GitHub.Client
  alias Varsel.GitHub.Installation
  alias Varsel.Test.GitHubApp

  defp unique(handle), do: "#{handle}#{System.unique_integer([:positive])}"

  defp sign_in(handle, token),
    do: sign_in_with_github(unique(handle), System.unique_integer([:positive]), %{"access_token" => token})

  defp reached(user),
    do: user |> then(&GitHub.list_user_installations!(actor: &1)) |> Enum.map(& &1.installation_id) |> Enum.sort()

  defp repositories(actor) do
    [actor: actor]
    |> GitHub.list_installation_repositories!()
    |> Enum.map(&{&1.installation_id, to_string(&1.repo)})
    |> Enum.sort()
  end

  defp synced_at(user), do: Ash.reload!(user, authorize?: false).github_installations_synced_at

  defp sync, do: Oban.drain_queue(queue: :github_sync)

  defp signal_jobs(user) do
    [worker: AshOban.Signals.Worker, queue: :github_sync]
    |> all_enqueued()
    |> Enum.filter(&(&1.args["payload"]["user_id"] == user.id))
  end

  defp installation_json(id, login, selection, extra \\ %{}) do
    Map.merge(
      %{
        "id" => id,
        "account" => %{"login" => login},
        "target_type" => "Organization",
        "repository_selection" => selection,
        "suspended_at" => nil
      },
      extra
    )
  end

  defp repositories_json(owner, names),
    do: %{
      "total_count" => length(names),
      "repositories" => Enum.map(names, &%{"name" => &1, "owner" => %{"login" => owner}})
    }

  test "rows are refused to an anonymous caller and hidden from another user" do
    GitHubApp.seed_installation(%{id: 7, account: "acme"})
    jdoe = register_user(unique("jdoe"))
    other = register_user(unique("other"), :supporter)
    poc = register_user(unique("poc"), :poc)
    GitHubApp.seed_user_installations(jdoe, [7])

    assert {:error, %Forbidden{}} = GitHub.list_user_installations(actor: nil)
    assert reached(jdoe) == [7]
    assert reached(other) == []
    assert reached(poc) == [7]
  end

  describe "a GitHub sign-in" do
    test "stores the installations, their repositories and the links on an empty database" do
      test_pid = self()
      poc = register_user(unique("poc"), :poc)
      Oban.drain_queue(queue: :github_sync)

      Req.Test.stub(Client, fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)
        send(test_pid, {:github, conn.method, conn.request_path, conn.query_params["page"]})
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_jdoe"]

        case {conn.method, conn.request_path, conn.query_params["page"]} do
          {"GET", "/user/installations", "1"} ->
            conn
            |> Plug.Conn.put_resp_header(
              "link",
              ~s(<https://api.github.com/user/installations?per_page=100&page=2>; rel="next")
            )
            |> Req.Test.json(%{"installations" => [installation_json(7, "acme", "all")]})

          {"GET", "/user/installations", "2"} ->
            Req.Test.json(conn, %{
              "installations" => [
                installation_json(8, "jdoe", "selected", %{"target_type" => "User"})
              ]
            })

          {"GET", "/user/installations/8/repositories", "1"} ->
            Req.Test.json(conn, repositories_json("jdoe", ["lib"]))
        end
      end)

      user = sign_in("jdoe", "gho_jdoe")
      assert [%{args: %{"listener" => "sync_github_installations"}}] = signal_jobs(user)
      assert synced_at(user) == nil

      assert %{success: 1, failure: 0} = Oban.drain_queue(queue: :github_sync)
      assert_received {:github, "GET", "/user/installations", "1"}
      assert_received {:github, "GET", "/user/installations", "2"}
      assert_received {:github, "GET", "/user/installations/8/repositories", "1"}
      refute_received {:github, _method, _path, _page}

      assert [
               %Installation{id: 7, kind: :organization, repository_selection: :all},
               %Installation{id: 8, kind: :user, repository_selection: :selected}
             ] = GitHub.list_installations!(actor: poc, query: [sort: [id: :asc]])

      assert repositories(poc) == [{8, "lib"}]
      assert reached(user) == [7, 8]

      assert {:ok, %Installation{id: 8}} =
               GitHub.installation_for_repository("jdoe", "lib", actor: user)

      assert %DateTime{} = synced_at(user)
    end

    test "syncs a person again who was synced ten minutes ago" do
      test_pid = self()

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert {conn.method, conn.request_path} == {"GET", "/user/installations"}
        Req.Test.json(conn, %{"installations" => []})
      end)

      handle = unique("jdoe")
      sub = System.unique_integer([:positive])
      user = sign_in_with_github(handle, sub, %{"access_token" => "gho_jdoe"})
      assert %{success: 1} = Oban.drain_queue(queue: :github_sync)
      assert_received {:github, "GET", "/user/installations"}

      Varsel.Repo.update_all(
        from(row in "users", where: row.id == type(^user.id, :binary_id)),
        set: [github_installations_synced_at: DateTime.shift(DateTime.utc_now(), minute: -10)]
      )

      sign_in_with_github(handle, sub, %{"access_token" => "gho_jdoe"})

      assert %{success: 1, cancelled: 0} = Oban.drain_queue(queue: :github_sync)
      assert_received {:github, "GET", "/user/installations"}
      assert DateTime.after?(synced_at(user), DateTime.shift(DateTime.utc_now(), minute: -1))
    end

    test "runs its job under authorization, through the Oban bypass" do
      Req.Test.stub(Client, fn conn ->
        assert {conn.method, conn.request_path} == {"GET", "/user/installations"}
        Req.Test.json(conn, %{"installations" => []})
      end)

      handle = unique("jdoe")

      user =
        Varsel.Accounts.register_user_with_github!(
          %{
            user_info: %{
              "sub" => System.unique_integer([:positive]),
              "preferred_username" => handle,
              "name" => handle,
              "email" => "#{handle}@example.com"
            },
            oauth_tokens: %{"access_token" => "gho_jdoe"}
          },
          context: %{private: %{ash_authentication?: true}}
        )

      assert [%{args: %{"authorize?" => true}}] = signal_jobs(user)
      assert %{success: 1, failure: 0} = sync()
      assert %DateTime{} = synced_at(user)
    end

    test "adds no second job while the first one is pending" do
      test_pid = self()

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert {conn.method, conn.request_path} == {"GET", "/user/installations"}
        Req.Test.json(conn, %{"installations" => []})
      end)

      handle = unique("jdoe")
      sub = System.unique_integer([:positive])
      user = sign_in_with_github(handle, sub, %{"access_token" => "gho_jdoe"})
      sign_in_with_github(handle, sub, %{"access_token" => "gho_jdoe"})

      assert [_job] = signal_jobs(user)
      assert %{success: 1, failure: 0} = sync()
      assert_received {:github, "GET", "/user/installations"}
      refute_received {:github, _method, _path}
    end

    test "is the only sign-in that lists installations" do
      Req.Test.stub(Client, fn _conn -> flunk("a Hex.pm sign-in reached GitHub") end)

      user = sign_in_with_hex(unique("hexonly"), System.unique_integer([:positive]))

      assert all_enqueued(queue: :github_sync) == []
      AshOban.run_trigger(user, :sync_github_installations)
      assert %{cancelled: 1, success: 0, failure: 0} = sync()
      assert reached(user) == []
    end
  end

  describe ":sync_github_installations" do
    test "replaces the person's links with the ones GitHub lists now" do
      GitHubApp.seed_installation(%{id: 7, account: "acme"})
      user = sign_in("jdoe", "gho_jdoe")
      other = sign_in("other", "gho_other")
      GitHubApp.seed_user_installations(user, [7])
      GitHubApp.seed_user_installations(other, [7])

      Req.Test.stub(Client, fn conn ->
        assert {conn.method, conn.request_path} == {"GET", "/user/installations"}

        case Plug.Conn.get_req_header(conn, "authorization") do
          ["Bearer gho_jdoe"] ->
            Req.Test.json(conn, %{"installations" => [installation_json(8, "other", "all")]})

          ["Bearer gho_other"] ->
            Req.Test.json(conn, %{"installations" => [installation_json(7, "acme", "all")]})
        end
      end)

      assert %{failure: 0} = sync()
      assert reached(user) == [8]
      assert reached(other) == [7]
    end

    test "adds repositories but never removes one" do
      poc = register_user(unique("poc"), :poc)

      GitHubApp.seed_installation(%{id: 8, account: "acme", repository_selection: :selected},
        repositories: ["acme/hidden", "acme/lib"]
      )

      user = sign_in("jdoe", "gho_jdoe")

      Req.Test.stub(Client, fn conn ->
        case {conn.method, conn.request_path} do
          {"GET", "/user/installations"} ->
            Req.Test.json(conn, %{"installations" => [installation_json(8, "acme", "selected")]})

          {"GET", "/user/installations/8/repositories"} ->
            Req.Test.json(conn, repositories_json("acme", ["lib", "new"]))
        end
      end)

      assert %{failure: 0} = Oban.drain_queue(queue: :github_sync)
      assert repositories(poc) == [{8, "hidden"}, {8, "lib"}, {8, "new"}]
      assert reached(user) == [8]
    end

    test "removes the person's links when GitHub refuses their token" do
      GitHubApp.seed_installation(%{id: 7, account: "acme"})
      user = sign_in("jdoe", "gho_revoked")
      GitHubApp.seed_user_installations(user, [7])

      Req.Test.stub(Client, fn conn ->
        assert {conn.method, conn.request_path} == {"GET", "/user/installations"}
        conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{"message" => "Bad credentials"})
      end)

      assert %{success: 1, failure: 0} = sync()
      assert reached(user) == []
    end

    test "keeps the person's links and fails when GitHub answers an error" do
      GitHubApp.seed_installation(%{id: 7, account: "acme"})
      user = sign_in("jdoe", "gho_jdoe")
      GitHubApp.seed_user_installations(user, [7])

      Req.Test.stub(Client, fn conn ->
        assert {conn.method, conn.request_path} == {"GET", "/user/installations"}
        conn |> Plug.Conn.put_status(502) |> Req.Test.json(%{"message" => "Bad Gateway"})
      end)

      assert %{success: 0, failure: 1} = sync()
      assert reached(user) == [7]
      assert synced_at(user) == nil
    end
  end

  describe ":sync_github_installations run by the person" do
    test "stores what GitHub lists for their own token" do
      poc = register_user(unique("poc"), :poc)
      GitHubApp.seed_installation(%{id: 7, account: "gone"})
      user = sign_in("jdoe", "gho_jdoe")
      GitHubApp.seed_user_installations(user, [7])

      Req.Test.stub(Client, fn conn ->
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_jdoe"]

        case {conn.method, conn.request_path} do
          {"GET", "/user/installations"} ->
            Req.Test.json(conn, %{
              "installations" => [
                installation_json(8, "jdoe", "selected", %{"target_type" => "User"})
              ]
            })

          {"GET", "/user/installations/8/repositories"} ->
            Req.Test.json(conn, repositories_json("jdoe", ["lib"]))
        end
      end)

      assert {:ok, _user} = Varsel.Accounts.sync_github_installations(user, actor: user)
      assert reached(user) == [8]
      assert repositories(poc) == [{8, "lib"}]
      assert %DateTime{} = synced_at(user)
    end

    test "is refused to anyone else, a POC too" do
      user = sign_in("jdoe", "gho_jdoe")
      other = register_user(unique("other"), :supporter)
      poc = register_user(unique("poc"), :poc)
      Req.Test.stub(Client, fn _conn -> flunk("a refused sync reached GitHub") end)

      assert Varsel.Accounts.can_sync_github_installations?(user, user)
      refute Varsel.Accounts.can_sync_github_installations?(other, user)
      refute Varsel.Accounts.can_sync_github_installations?(poc, user)
      refute Varsel.Accounts.can_sync_github_installations?(nil, user)

      assert {:error, %Forbidden{}} =
               Varsel.Accounts.sync_github_installations(user, actor: other)

      assert {:error, %Forbidden{}} =
               Varsel.Accounts.sync_github_installations(user, actor: poc)

      assert synced_at(user) == nil
    end
  end

  describe "the scheduled trigger" do
    test "picks people with a GitHub identity whose last sync is an hour old or missing" do
      Req.Test.stub(Client, fn conn ->
        assert {conn.method, conn.request_path} == {"GET", "/user/installations"}
        Req.Test.json(conn, %{"installations" => []})
      end)

      sign_in("fresh", "gho_fresh")
      stale = sign_in("stale", "gho_stale")
      sign_in_with_hex(unique("hexonly"), System.unique_integer([:positive]))
      assert %{success: 2, failure: 0} = Oban.drain_queue(queue: :github_sync)
      unsynced = sign_in("unsynced", "gho_unsynced")
      Varsel.Repo.delete_all(Oban.Job)

      Varsel.Repo.update_all(
        from(user in "users", where: user.id == type(^stale.id, :binary_id)),
        set: [github_installations_synced_at: DateTime.shift(DateTime.utc_now(), minute: -61)]
      )

      assert :ok = perform_job(Varsel.Accounts.User.SyncGitHubInstallationsScheduler, %{})

      picked =
        [worker: Varsel.Accounts.User.SyncGitHubInstallationsWorker]
        |> all_enqueued()
        |> Enum.map(& &1.args["primary_key"]["id"])
        |> Enum.sort()

      assert picked == Enum.sort([stale.id, unsynced.id])
    end
  end
end
