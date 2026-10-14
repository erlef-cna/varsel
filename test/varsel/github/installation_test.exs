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
  alias Varsel.Test.GitHubApp

  setup do
    %{
      poc: register_user("poc#{System.unique_integer([:positive])}", :poc),
      supporter: register_user("supporter#{System.unique_integer([:positive])}", :supporter)
    }
  end

  defp installation_json(id, login) do
    %{
      "id" => id,
      "account" => %{"login" => login},
      "target_type" => "Organization",
      "repository_selection" => "all"
    }
  end

  defp minutes_from_now(minutes), do: DateTime.shift(DateTime.utc_now(), minute: minutes)

  test "a write without the sync stamp is refused, even to a POC", %{poc: poc} do
    attrs = %{id: 7, account: "acme", kind: :organization, repository_selection: :all}

    assert {:error, %Forbidden{}} =
             Ash.create(Varsel.GitHub.Installation, attrs, action: :store, actor: poc)

    assert {:error, %Forbidden{}} =
             Ash.create(Varsel.GitHub.InstallationLookup, %{subject: "acme", installation_id: 7},
               action: :store,
               actor: poc
             )
  end

  describe "installation_for_repository/2" do
    test "is refused to an anonymous caller", %{supporter: supporter} do
      Req.Test.stub(Client, fn _conn ->
        flunk("an anonymous lookup reached GitHub")
      end)

      assert {:error, %Forbidden{}} =
               GitHub.installation_for_repository("acme", "lib", actor: nil)

      refute GitHub.can_installation_for_repository?(nil, "acme", "lib")
      assert GitHub.can_installation_for_repository?(supporter, "acme", "lib")
    end

    test "asks GitHub once and answers from the cache after", %{supporter: supporter} do
      test_pid = self()

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert conn.method == "GET"
        assert conn.request_path == "/repos/acme/lib/installation"
        Req.Test.json(conn, installation_json(7, "acme"))
      end)

      assert {:ok, %{id: 7, kind: :organization}} =
               GitHub.installation_for_repository("acme", "lib", actor: supporter)

      assert_received {:github, "GET", "/repos/acme/lib/installation"}

      assert {:ok, %{id: 7}} = GitHub.installation_for_repository("Acme", "LIB", actor: supporter)
      refute_received {:github, _method, _path}
    end

    test "caches that the App is not installed", %{supporter: supporter} do
      test_pid = self()

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert conn.request_path == "/repos/acme/lib/installation"
        conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{"message" => "Not Found"})
      end)

      assert {:ok, nil} = GitHub.installation_for_repository("acme", "lib", actor: supporter)
      assert_received {:github, "GET", "/repos/acme/lib/installation"}

      assert {:ok, nil} = GitHub.installation_for_repository("acme", "lib", actor: supporter)
      refute_received {:github, _method, _path}
    end

    test "asks GitHub again once the answer is ten minutes old", %{poc: poc, supporter: supporter} do
      test_pid = self()

      GitHubApp.seed_installation(poc, %{id: 7, account: "acme"},
        repositories: ["acme/lib"],
        fetched_at: minutes_from_now(-11)
      )

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert conn.request_path == "/repos/acme/lib/installation"
        conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{"message" => "Not Found"})
      end)

      assert {:ok, nil} = GitHub.installation_for_repository("acme", "lib", actor: supporter)
      assert_received {:github, "GET", "/repos/acme/lib/installation"}
    end

    test "answers a seeded installation without asking GitHub", %{poc: poc, supporter: supporter} do
      Req.Test.stub(Client, fn _conn -> flunk("a seeded lookup reached GitHub") end)

      GitHubApp.seed_installation(poc, %{id: 7, account: "acme"},
        repositories: ["acme/lib"],
        token: "ghs_seeded"
      )

      GitHubApp.seed_not_installed(poc, "acme/other")

      assert {:ok, %{id: 7}} = GitHub.installation_for_repository("acme", "lib", actor: supporter)
      assert {:ok, %{id: 7}} = GitHub.installation_for_org("acme", actor: supporter)
      assert {:ok, nil} = GitHub.installation_for_repository("acme", "other", actor: supporter)
      assert GitHub.installation_token(7, actor: poc) == {:ok, "ghs_seeded"}
    end

    test "shows the stored token to a POC only", %{poc: poc, supporter: supporter} do
      GitHubApp.seed_installation(poc, %{id: 7, account: "acme"},
        repositories: ["acme/lib"],
        token: "ghs_seeded"
      )

      assert {:ok, %{token: %Ash.ForbiddenField{}}} =
               GitHub.installation_for_repository("acme", "lib", actor: supporter)

      assert {:ok, %{token: "ghs_seeded"}} =
               GitHub.installation_for_repository("acme", "lib", actor: poc)
    end

    test "answers nil without a request when the App has no private key", %{supporter: supporter} do
      config = Application.fetch_env!(:varsel, :github)
      Application.put_env(:varsel, :github, Keyword.delete(config, :private_key))
      on_exit(fn -> Application.put_env(:varsel, :github, config) end)
      Req.Test.stub(Client, fn _conn -> flunk("an inert App reached GitHub") end)

      assert {:ok, nil} = GitHub.installation_for_repository("acme", "lib", actor: supporter)
      assert {:ok, nil} = GitHub.installation_for_org("acme", actor: supporter)
    end
  end

  describe "installation_token/1" do
    test "is refused to a supporter and to an anonymous caller", %{poc: poc, supporter: supporter} do
      Req.Test.stub(Client, fn _conn -> flunk("a refused caller reached GitHub") end)

      GitHubApp.seed_installation(poc, %{id: 7, account: "acme"}, token: "ghs_seeded")

      assert {:error, %Forbidden{}} = GitHub.installation_token(7, actor: supporter)
      assert {:error, %Forbidden{}} = GitHub.installation_token(7, actor: nil)
      refute GitHub.can_installation_token?(supporter, 7)
      refute GitHub.can_installation_token?(nil, 7)
      assert GitHub.can_installation_token?(poc, 7)
    end

    test "mints a token for a POC and answers from the cache after", %{poc: poc} do
      test_pid = self()
      GitHubApp.seed_installation(poc, %{id: 7, account: "acme"})

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})
        assert conn.method == "POST"
        assert conn.request_path == "/app/installations/7/access_tokens"

        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{
          "token" => "ghs_minted",
          "expires_at" => DateTime.to_iso8601(minutes_from_now(60))
        })
      end)

      assert GitHub.installation_token(7, actor: poc) == {:ok, "ghs_minted"}
      assert_received {:github, "POST", "/app/installations/7/access_tokens"}

      assert GitHub.installation_token(7, actor: poc) == {:ok, "ghs_minted"}
      refute_received {:github, _method, _path}
    end

    test "mints a new token when the stored one expires within five minutes", %{poc: poc} do
      test_pid = self()

      GitHubApp.seed_installation(poc, %{id: 7, account: "acme"},
        token: "ghs_old",
        token_expires_at: minutes_from_now(4)
      )

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})

        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{
          "token" => "ghs_new",
          "expires_at" => DateTime.to_iso8601(minutes_from_now(60))
        })
      end)

      assert GitHub.installation_token(7, actor: poc) == {:ok, "ghs_new"}
      assert_received {:github, "POST", "/app/installations/7/access_tokens"}
    end

    test "refuses an installation that no lookup stored", %{poc: poc} do
      Req.Test.stub(Client, fn _conn ->
        flunk("an unknown installation reached GitHub")
      end)

      assert {:error, %Invalid{errors: [%Ash.Error.Query.NotFound{}]}} =
               GitHub.installation_token(99, actor: poc)
    end
  end

  describe "public_read_token/0" do
    test "mints the home organization's token for anyone", %{supporter: supporter} do
      test_pid = self()

      Req.Test.stub(Client, fn conn ->
        send(test_pid, {:github, conn.method, conn.request_path})

        case {conn.method, conn.request_path} do
          {"GET", "/orgs/erlef-cna/installation"} ->
            Req.Test.json(conn, installation_json(11, "erlef-cna"))

          {"POST", "/app/installations/11/access_tokens"} ->
            conn
            |> Plug.Conn.put_status(201)
            |> Req.Test.json(%{
              "token" => "ghs_public",
              "expires_at" => DateTime.to_iso8601(minutes_from_now(60))
            })
        end
      end)

      assert GitHub.can_public_read_token?(nil)
      assert GitHub.can_public_read_token?(supporter)

      assert GitHub.public_read_token(actor: nil) == {:ok, "ghs_public"}
      assert_received {:github, "GET", "/orgs/erlef-cna/installation"}
      assert_received {:github, "POST", "/app/installations/11/access_tokens"}

      assert GitHub.public_read_token(actor: supporter) == {:ok, "ghs_public"}
      refute_received {:github, _method, _path}
    end

    test "fails when the App is not installed on the home organization" do
      Req.Test.stub(Client, fn conn ->
        assert conn.request_path == "/orgs/erlef-cna/installation"
        conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{"message" => "Not Found"})
      end)

      assert {:error,
              %Invalid{
                errors: [%Varsel.GitHub.Errors.NotInstalled{account: "erlef-cna"}]
              }} =
               GitHub.public_read_token(actor: nil)
    end
  end
end
