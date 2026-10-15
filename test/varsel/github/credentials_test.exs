# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.CredentialsTest do
  @moduledoc """
  The credential each GitHub request runs with, row by row of the rules:
  a repository request for a POC and for everyone else, and a request
  about no particular repository.
  """

  # Swaps the :github config for the unconfigured App.
  use Varsel.DataCase, async: false

  alias Varsel.Fixtures
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.Credentials
  alias Varsel.Test.GitHubApi
  alias Varsel.Test.GitHubApp

  @own "Bearer gho_token"
  @installation_token "ghs_acme_lib"
  @installation "Bearer " <> @installation_token

  setup do
    hex_poc = Fixtures.sign_in_with_hex("credentials_hex", "credentials_hex")

    %{
      poc: Fixtures.register_user("credentials_poc", :poc),
      supporter: Fixtures.register_user("credentials_supporter", :supporter),
      hex_poc: Ash.update!(hex_poc, %{role: :poc}, action: :set_role, authorize?: false)
    }
  end

  defp install_on_acme_lib do
    GitHubApp.seed_installation(%{id: 7, account: "acme", repository_selection: :selected},
      repositories: ["acme/acme_lib"],
      token: @installation_token
    )
  end

  # Records every advisory read with the token it carried, and answers each
  # with `answer` for that token.
  defp stub(answer) do
    test_pid = self()

    GitHubApi.stub(fn %{path_info: ["repos", "acme", "acme_lib", "security-advisories", _ghsa_id]} =
                        conn ->
      [authorization] = Plug.Conn.get_req_header(conn, "authorization")
      send(test_pid, {:github, authorization})
      answer.(conn, authorization)
    end)
  end

  defp fetch(actor) do
    Credentials.run(actor, "acme", "acme_lib", fn %{token: token} ->
      Advisories.fetch("acme", "acme_lib", "GHSA-2cfg-hjmp-qrvw", token: token)
    end)
  end

  defp ok(conn, _authorization), do: Req.Test.json(conn, %{"ghsa_id" => "GHSA-2cfg-hjmp-qrvw"})

  defp refuse(status) do
    fn conn, authorization ->
      case authorization do
        @installation ->
          ok(conn, authorization)

        _own_token ->
          conn |> Plug.Conn.put_status(status) |> Req.Test.json(%{"message" => "No"})
      end
    end
  end

  describe "a repository request for someone who is no POC" do
    test "runs with their own token when their login reaches the installation", %{
      supporter: supporter
    } do
      install_on_acme_lib()
      GitHubApp.seed_user_installations(supporter, [7])
      stub(&ok/2)

      assert Credentials.reach(supporter, "acme", "acme_lib") == :user
      assert {:user, {:ok, _advisory}} = fetch(supporter)
      assert_received {:github, @own}
    end

    test "is not tried again with another credential after a refusal", %{supporter: supporter} do
      install_on_acme_lib()
      GitHubApp.seed_user_installations(supporter, [7])

      for status <- [404, 403] do
        stub(refuse(status))

        assert {:user, answer} = fetch(supporter)
        assert answer in [:not_found, {:error, {:http, 403, %{"message" => "No"}}}]
        assert_received {:github, @own}
        refute_received {:github, _authorization}
      end
    end

    test "has no credential when their login does not reach the installation", %{
      supporter: supporter
    } do
      install_on_acme_lib()
      stub(&ok/2)

      assert Credentials.reach(supporter, "acme", "acme_lib") == :not_reachable
      assert fetch(supporter) == {:no_credential, :not_reachable}
      refute_received {:github, _authorization}
    end

    test "has no credential when the App is not on the repository", %{supporter: supporter} do
      stub(&ok/2)

      assert Credentials.reach(supporter, "acme", "acme_lib") == :not_reachable
      assert fetch(supporter) == {:no_credential, :not_reachable}
      refute_received {:github, _authorization}
    end

    test "has no credential without a GitHub identity, and nothing runs anonymously" do
      install_on_acme_lib()
      stub(&ok/2)

      hex_supporter =
        Fixtures.sign_in_with_hex("credentials_hex_supporter", "credentials_hex_supporter")

      assert Credentials.reach(hex_supporter, "acme", "acme_lib") == :no_github_identity
      assert fetch(hex_supporter) == {:no_credential, :no_github_identity}
      assert Credentials.reach(nil, "acme", "acme_lib") == :no_github_identity
      assert fetch(nil) == {:no_credential, :no_github_identity}
      refute_received {:github, _authorization}
    end
  end

  describe "a repository request for a POC" do
    setup %{poc: poc} do
      install_on_acme_lib()
      GitHubApp.seed_user_installations(poc, [7])
      :ok
    end

    test "runs with their own token when their login reaches the installation", %{poc: poc} do
      stub(&ok/2)

      assert Credentials.reach(poc, "acme", "acme_lib") == :user
      assert {:user, {:ok, _advisory}} = fetch(poc)
      assert_received {:github, @own}
      refute_received {:github, _authorization}
    end

    test "runs once more with the installation token after a 404 or a 403", %{poc: poc} do
      for status <- [404, 403] do
        stub(refuse(status))

        assert {:installation, {:ok, _advisory}} = fetch(poc)
        assert_received {:github, @own}
        assert_received {:github, @installation}
      end
    end

    test "is not tried again after another failure", %{poc: poc} do
      stub(refuse(500))

      assert {:user, {:error, {:http, 500, _body}}} = fetch(poc)
      assert_received {:github, @own}
      refute_received {:github, _authorization}
    end

    test "tries the installation token once only", %{poc: poc} do
      stub(fn conn, _authorization -> Plug.Conn.send_resp(conn, 404, "{}") end)

      assert {:installation, :not_found} = fetch(poc)
      assert_received {:github, @own}
      assert_received {:github, @installation}
      refute_received {:github, _authorization}
    end

    test "runs with the installation token when their login does not reach the installation" do
      other_poc = Fixtures.register_user("credentials_other_poc", :poc)
      stub(&ok/2)

      assert Credentials.reach(other_poc, "acme", "acme_lib") == :installation

      assert {:ok, %{kind: :installation, token: @installation_token}} =
               Credentials.repository(other_poc, "acme", "acme_lib")

      assert {:installation, {:ok, _advisory}} = fetch(other_poc)
      assert_received {:github, @installation}
      refute_received {:github, _authorization}
    end

    test "has no credential when the App is not on the repository", %{poc: poc} do
      assert Credentials.reach(poc, "acme", "other_lib") == :not_installed

      assert Credentials.run(poc, "acme", "other_lib", fn _credential ->
               flunk("GitHub was asked")
             end) ==
               {:no_credential, :not_installed}
    end

    test "runs with the installation token without a GitHub identity", %{hex_poc: hex_poc} do
      stub(&ok/2)

      assert Credentials.reach(hex_poc, "acme", "acme_lib") == :installation
      assert {:installation, {:ok, _advisory}} = fetch(hex_poc)
      assert_received {:github, @installation}

      assert Credentials.reach(hex_poc, "acme", "other_lib") == :not_installed
    end
  end

  describe "a request before its repository is known" do
    test "may be tried by a person with a GitHub identity or a POC", %{
      poc: poc,
      hex_poc: hex_poc,
      supporter: supporter
    } do
      assert Credentials.may_try?(poc)
      assert Credentials.may_try?(hex_poc)
      assert Credentials.may_try?(supporter)

      refute Credentials.may_try?(Fixtures.sign_in_with_hex("credentials_hex_other", "credentials_hex_other"))

      refute Credentials.may_try?(nil)
    end
  end

  describe "a request about no particular repository" do
    test "runs with the home organization's installation token for anyone" do
      token = "ghs_erlef_cna"
      GitHubApp.seed_installation(%{id: 1, account: "erlef-cna"}, token: token)

      assert Credentials.public_read() == {:ok, %{kind: :public_read, token: token}}
      assert Credentials.public_read_or_anonymous() == {:ok, token}
    end

    test "has no credential when the home organization has no installation" do
      assert Credentials.public_read() == {:error, :not_configured}
      assert Credentials.public_read_or_anonymous() == {:error, :not_configured}
    end

    test "runs anonymously only when the App is not configured" do
      config = Application.get_env(:varsel, :github)
      on_exit(fn -> Application.put_env(:varsel, :github, config) end)
      Application.put_env(:varsel, :github, Keyword.drop(config, [:app_id, :private_key]))

      assert Credentials.public_read_or_anonymous() == {:ok, nil}
    end
  end
end
