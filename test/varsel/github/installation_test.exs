# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.InstallationTest do
  # Swaps the :github config for the unconfigured case.
  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.GitHub
  alias Varsel.GitHub.Client
  alias Varsel.GitHub.Installation
  alias Varsel.Test.GitHubApp

  setup do
    %{
      poc: register_user("poc#{System.unique_integer([:positive])}", :poc),
      supporter: register_user("supporter#{System.unique_integer([:positive])}", :supporter)
    }
  end

  defp minutes_from_now(minutes), do: DateTime.shift(DateTime.utc_now(), minute: minutes)

  defp ids(installations), do: installations |> Enum.map(& &1.id) |> Enum.sort()

  defp minted(conn, token) do
    conn
    |> Plug.Conn.put_status(201)
    |> Req.Test.json(%{
      "token" => token,
      "expires_at" => DateTime.to_iso8601(minutes_from_now(60))
    })
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

  defp next_link(conn, url, page),
    do: Plug.Conn.put_resp_header(conn, "link", ~s(<https://api.github.com#{url}?per_page=100&page=#{page}>; rel="next"))

  # Runs the scheduled worker alone. Each GitHub sign-in in the setup also
  # queued a user sync on the same queue.
  defp run_sync, do: perform_job(Varsel.GitHub.Installation.SyncAllWorker, %{})

  describe "reads" do
    setup %{supporter: supporter} do
      GitHubApp.seed_installation(%{id: 7, account: "acme"})

      GitHubApp.seed_installation(%{id: 8, account: "other", repository_selection: :selected},
        repositories: ["other/app"]
      )

      GitHubApp.seed_user_installations(supporter, [7])
      :ok
    end

    test "are refused to an anonymous caller" do
      assert {:error, %Forbidden{}} = GitHub.list_installations(actor: nil)

      assert {:error, %Forbidden{}} =
               GitHub.installation_for_repository("acme", "lib", actor: nil)

      assert {:error, %Forbidden{}} = GitHub.installation_for_account("acme", actor: nil)
      assert {:error, %Forbidden{}} = GitHub.list_installation_repositories(actor: nil)
      refute GitHub.can_installation_for_repository?(nil, "acme", "lib")
    end

    test "show a supporter only the installations their GitHub token reaches", %{
      supporter: supporter
    } do
      assert supporter |> then(&GitHub.list_installations!(actor: &1)) |> ids() == [7]

      assert {:ok, %Installation{id: 7}} =
               GitHub.installation_for_repository("acme", "lib", actor: supporter)

      assert {:ok, nil} = GitHub.installation_for_repository("other", "app", actor: supporter)
      assert {:ok, nil} = GitHub.installation_for_account("other", actor: supporter)
      assert GitHub.list_installation_repositories!(actor: supporter) == []
    end

    test "show a POC every installation", %{poc: poc} do
      assert poc |> then(&GitHub.list_installations!(actor: &1)) |> ids() == [7, 8]

      assert {:ok, %Installation{id: 8}} =
               GitHub.installation_for_repository("other", "app", actor: poc)

      assert [%{owner: owner, repo: repo}] = GitHub.list_installation_repositories!(actor: poc)
      assert {to_string(owner), to_string(repo)} == {"other", "app"}
    end

    test "show the stored token to a POC only", %{poc: poc, supporter: supporter} do
      GitHubApp.seed_installation(%{id: 7, account: "acme"}, token: "ghs_seeded")

      assert {:ok, %{token: %Ash.ForbiddenField{}}} =
               GitHub.get_installation(7, actor: supporter, load: [:token])

      assert {:ok, %{token: "ghs_seeded"}} =
               GitHub.get_installation(7, actor: poc, load: [:token])
    end
  end

  describe "writes" do
    test "are refused to a POC outside the syncs", %{poc: poc, supporter: supporter} do
      installation = GitHubApp.seed_installation(%{id: 7, account: "acme"})
      [link] = GitHubApp.seed_user_installations(supporter, [7])
      attrs = %{id: 9, account: "acme", kind: :organization, repository_selection: :all}
      stamp = %{private: %{github_sync: true}}

      assert {:error, %Forbidden{}} = GitHub.sync_installation(attrs, actor: poc)
      assert {:error, %Forbidden{}} = GitHub.forget_installation(installation, actor: poc)

      assert {:error, %Forbidden{}} =
               GitHub.forget_installation(installation, actor: poc, context: stamp)

      assert {:error, %Forbidden{}} =
               GitHub.store_installation_token(installation, %{token: "ghs_forged"}, actor: poc)

      assert {:error, %Forbidden{}} =
               GitHub.sync_installation_repository(
                 %{installation_id: 7, owner: "acme", repo: "lib"},
                 actor: poc
               )

      assert {:error, %Forbidden{}} =
               GitHub.sync_user_installation(%{user_id: supporter.id, installation_id: 7},
                 actor: poc,
                 context: stamp
               )

      assert {:error, %Forbidden{}} =
               GitHub.forget_user_installation(link, actor: poc, context: stamp)

      assert {:error, %Forbidden{}} = GitHub.sync_installations(actor: poc)

      assert {:error, %Forbidden{}} =
               Varsel.Accounts.sync_github_installations(supporter, actor: poc)
    end
  end

  describe "installation_for_repository/2" do
    test "answers an installation on all repositories for any repository of its account", %{
      poc: poc
    } do
      GitHubApp.seed_installation(%{id: 7, account: "acme"})

      assert {:ok, %Installation{id: 7}} =
               GitHub.installation_for_repository("acme", "lib", actor: poc)

      assert {:ok, %Installation{id: 7}} =
               GitHub.installation_for_repository("Acme", "LIB", actor: poc)

      assert {:ok, nil} = GitHub.installation_for_repository("other", "lib", actor: poc)
    end

    test "answers a selective installation for its listed repositories only", %{poc: poc} do
      GitHubApp.seed_installation(
        %{id: 8, account: "jdoe", kind: :user, repository_selection: :selected},
        repositories: ["jdoe/lib"]
      )

      assert {:ok, %Installation{id: 8, kind: :user}} =
               GitHub.installation_for_repository("JDoe", "Lib", actor: poc)

      assert {:ok, nil} = GitHub.installation_for_repository("jdoe", "other", actor: poc)
    end

    test "answers nil for a suspended installation", %{poc: poc} do
      GitHubApp.seed_installation(%{id: 7, account: "acme", suspended_at: minutes_from_now(-60)})

      assert {:ok, nil} = GitHub.installation_for_repository("acme", "lib", actor: poc)
      assert {:ok, nil} = GitHub.installation_for_account("acme", actor: poc)
    end
  end

  describe "installation_token/1" do
    test "is refused to a supporter and to an anonymous caller", %{poc: poc, supporter: supporter} do
      Req.Test.stub(Client, fn _conn -> flunk("a refused caller reached GitHub") end)
      GitHubApp.seed_installation(%{id: 7, account: "acme"}, token: "ghs_seeded")
      GitHubApp.seed_user_installations(supporter, [7])

      assert {:error, %Forbidden{}} = GitHub.installation_token(7, actor: supporter)
      assert {:error, %Forbidden{}} = GitHub.installation_token(7, actor: nil)
      refute GitHub.can_installation_token?(supporter, 7)
      refute GitHub.can_installation_token?(nil, 7)
      assert GitHub.can_installation_token?(poc, 7)
      assert GitHub.installation_token(7, actor: poc) == {:ok, "ghs_seeded"}
    end

    test "mints a token for a POC and answers the stored token after", %{poc: poc} do
      test_pid = self()
      GitHubApp.seed_installation(%{id: 7, account: "acme"})

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert {conn.method, conn.request_path} == {"POST", "/app/installations/7/access_tokens"}
        minted(conn, "ghs_minted")
      end)

      assert GitHub.installation_token(7, actor: poc) == {:ok, "ghs_minted"}
      assert_received {:github, "POST", "/app/installations/7/access_tokens"}

      assert GitHub.installation_token(7, actor: poc) == {:ok, "ghs_minted"}
      refute_received {:github, _method, _path}
    end

    test "stores the token encrypted", %{poc: poc} do
      GitHubApp.seed_installation(%{id: 7, account: "acme"}, token: "ghs_seeded")

      %{rows: [[stored]]} =
        Varsel.Repo.query!("SELECT encrypted_token FROM github_installations WHERE id = 7")

      assert :binary.match(stored, "ghs_seeded") == :nomatch

      assert {:ok, %{token: "ghs_seeded"}} =
               GitHub.get_installation(7, actor: poc, load: [:token])
    end

    test "mints a new token when the stored one expires within five minutes", %{poc: poc} do
      test_pid = self()

      GitHubApp.seed_installation(%{id: 7, account: "acme"},
        token: "ghs_old",
        token_expires_at: minutes_from_now(4)
      )

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert {conn.method, conn.request_path} == {"POST", "/app/installations/7/access_tokens"}
        minted(conn, "ghs_new")
      end)

      assert GitHub.installation_token(7, actor: poc) == {:ok, "ghs_new"}
      assert_received {:github, "POST", "/app/installations/7/access_tokens"}
    end

    test "mints once for concurrent callers", %{poc: poc} do
      test_pid = self()
      GitHubApp.seed_installation(%{id: 7, account: "acme"})

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert {conn.method, conn.request_path} == {"POST", "/app/installations/7/access_tokens"}
        minted(conn, "ghs_once")
      end)

      tokens =
        1..5
        |> Enum.map(fn _caller ->
          Task.async(fn -> GitHub.installation_token(7, actor: poc) end)
        end)
        |> Task.await_many()

      assert tokens == List.duplicate({:ok, "ghs_once"}, 5)
      assert_received {:github, "POST", "/app/installations/7/access_tokens"}
      refute_received {:github, _method, _path}
    end

    test "refuses an installation that is not stored", %{poc: poc} do
      Req.Test.stub(Client, fn _conn -> flunk("an unknown installation reached GitHub") end)

      assert {:error, %Invalid{errors: [%Ash.Error.Query.NotFound{}]}} =
               GitHub.installation_token(99, actor: poc)
    end
  end

  describe "public_read_token/0" do
    test "mints the home organization's token for anyone", %{supporter: supporter} do
      test_pid = self()
      GitHubApp.seed_installation(%{id: 11, account: "erlef-cna"})

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert {conn.method, conn.request_path} == {"POST", "/app/installations/11/access_tokens"}
        minted(conn, "ghs_public")
      end)

      assert GitHub.can_public_read_token?(nil)
      assert GitHub.can_public_read_token?(supporter)

      assert GitHub.public_read_token(actor: nil) == {:ok, "ghs_public"}
      assert_received {:github, "POST", "/app/installations/11/access_tokens"}

      assert GitHub.public_read_token(actor: supporter) == {:ok, "ghs_public"}
      refute_received {:github, _method, _path}
    end

    test "fails when the App is not installed on the home organization" do
      Req.Test.stub(Client, fn _conn -> flunk("a missing installation reached GitHub") end)

      assert {:error, %Invalid{errors: [%Varsel.GitHub.Errors.NotInstalled{account: "erlef-cna"}]}} =
               GitHub.public_read_token(actor: nil)
    end
  end

  describe "sync_all" do
    test "replaces the installations and the repositories of selective ones", %{poc: poc} do
      test_pid = self()

      GitHubApp.seed_installation(%{id: 5, account: "gone"})

      GitHubApp.seed_installation(
        %{id: 8, account: "jdoe", kind: :user, repository_selection: :selected},
        repositories: ["jdoe/dropped", "jdoe/kept"],
        token: "ghs_jdoe"
      )

      Req.Test.stub(Client, fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)
        send(test_pid, {:github, conn.method, conn.request_path, conn.query_params["page"]})

        case {conn.method, conn.request_path, conn.query_params["page"]} do
          {"GET", "/app/installations", "1"} ->
            ["Bearer " <> _jwt] = Plug.Conn.get_req_header(conn, "authorization")

            conn
            |> next_link("/app/installations", 2)
            |> Req.Test.json([installation_json(7, "acme", "all")])

          {"GET", "/app/installations", "2"} ->
            Req.Test.json(conn, [
              installation_json(8, "JDoe", "selected", %{"target_type" => "User"}),
              installation_json(9, "paused", "selected", %{
                "suspended_at" => "2026-10-01T00:00:00Z"
              })
            ])

          {"GET", "/installation/repositories", "1"} ->
            assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer ghs_jdoe"]

            conn
            |> next_link("/installation/repositories", 2)
            |> Req.Test.json(%{
              "total_count" => 2,
              "repositories" => [%{"name" => "kept", "owner" => %{"login" => "jdoe"}}]
            })

          {"GET", "/installation/repositories", "2"} ->
            Req.Test.json(conn, %{
              "total_count" => 2,
              "repositories" => [%{"name" => "added", "owner" => %{"login" => "jdoe"}}]
            })
        end
      end)

      assert :ok = run_sync()

      assert_received {:github, "GET", "/app/installations", "1"}
      assert_received {:github, "GET", "/app/installations", "2"}
      assert_received {:github, "GET", "/installation/repositories", "1"}
      assert_received {:github, "GET", "/installation/repositories", "2"}
      refute_received {:github, _method, _path, _page}

      installations = GitHub.list_installations!(actor: poc, query: [sort: [id: :asc]])

      assert [
               %{
                 id: 7,
                 account: acme,
                 kind: :organization,
                 repository_selection: :all,
                 suspended_at: nil
               },
               %{id: 8, account: jdoe, kind: :user, repository_selection: :selected},
               %{id: 9, suspended_at: ~U[2026-10-01 00:00:00.000000Z]}
             ] = installations

      assert {to_string(acme), to_string(jdoe)} == {"acme", "JDoe"}

      repositories =
        [actor: poc]
        |> GitHub.list_installation_repositories!()
        |> Enum.map(&{&1.installation_id, to_string(&1.repo)})
        |> Enum.sort()

      assert repositories == [{8, "added"}, {8, "kept"}]
      assert {:ok, nil} = GitHub.installation_for_account("gone", actor: poc)
    end

    test "mints a token for a selective installation that has none", %{poc: poc} do
      test_pid = self()

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})

        case {conn.method, conn.request_path} do
          {"GET", "/app/installations"} ->
            Req.Test.json(conn, [installation_json(8, "jdoe", "selected")])

          {"POST", "/app/installations/8/access_tokens"} ->
            minted(conn, "ghs_synced")

          {"GET", "/installation/repositories"} ->
            assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer ghs_synced"]

            Req.Test.json(conn, %{
              "total_count" => 1,
              "repositories" => [%{"name" => "lib", "owner" => %{"login" => "jdoe"}}]
            })
        end
      end)

      assert :ok = run_sync()
      assert_received {:github, "POST", "/app/installations/8/access_tokens"}

      assert {:ok, %Installation{id: 8}} =
               GitHub.installation_for_repository("jdoe", "lib", actor: poc)

      assert GitHub.installation_token(8, actor: poc) == {:ok, "ghs_synced"}
    end

    test "does nothing when the App has no private key", %{poc: poc} do
      config = Application.fetch_env!(:varsel, :github)
      Application.put_env(:varsel, :github, Keyword.delete(config, :private_key))
      on_exit(fn -> Application.put_env(:varsel, :github, config) end)
      Req.Test.stub(Client, fn _conn -> flunk("an inert App reached GitHub") end)

      GitHubApp.seed_installation(%{id: 7, account: "acme"})

      assert :ok = run_sync()
      assert poc |> then(&GitHub.list_installations!(actor: &1)) |> ids() == [7]
    end
  end
end
