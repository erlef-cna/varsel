# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AccountSettingsLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Varsel.Fixtures

  alias Ash.Error.Forbidden
  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Accounts
  alias Varsel.Accounts.User

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  # A second provider on the same account, reporting a different address —
  # which is the only way a user has more than one to choose between.
  defp link_hex_identity(user, username, email) do
    Ash.create!(
      Varsel.Accounts.UserIdentity,
      %{
        user_id: user.id,
        strategy: "hex",
        user_info: %{"sub" => username, "preferred_username" => username, "email" => email},
        oauth_tokens: %{"access_token" => "token"}
      },
      action: :upsert,
      authorize?: false
    )
  end

  test "an anonymous visitor is refused", %{conn: conn} do
    assert_raise VarselWeb.UnauthorizedError, fn -> live(conn, ~p"/settings/account") end
  end

  test "lists every address a linked provider reported", %{conn: conn} do
    user = register_user("alice")
    link_hex_identity(user, "alice_hex", "alice@hex.example")

    {:ok, _lv, html} = conn |> log_in(user) |> live(~p"/settings/account")

    assert html =~ "alice@example.com"
    assert html =~ "alice@hex.example"
  end

  test "choosing an address sets it as the notification email", %{conn: conn} do
    user = register_user("alice")
    link_hex_identity(user, "alice_hex", "alice@hex.example")

    {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/account")

    html =
      lv
      |> element(~s{button[phx-value-notification_email="alice@hex.example"]})
      |> render_click()

    assert html =~ "Notification email set to alice@hex.example"

    assert to_string(Ash.get!(User, user.id, authorize?: false).notification_email) ==
             "alice@hex.example"
  end

  test "an address no linked provider reported is refused" do
    user = register_user("alice")

    assert {:error, _error} =
             Accounts.set_user_notification_email(
               user,
               %{notification_email: "attacker@example.com"},
               actor: user
             )

    assert to_string(Ash.get!(User, user.id, authorize?: false).notification_email) ==
             "alice@example.com"
  end

  test "nobody sets someone else's notification email" do
    alice = register_user("alice")
    poc = register_user("poc", :poc)
    link_hex_identity(alice, "alice_hex", "alice@hex.example")

    assert {:error, %Forbidden{}} =
             Accounts.set_user_notification_email(
               alice,
               %{notification_email: "alice@hex.example"},
               actor: poc
             )
  end

  describe "unlinking a provider" do
    defp identities(user) do
      user
      |> Ash.load!([:identities], authorize?: false)
      |> Map.fetch!(:identities)
    end

    # The providers section only lists what this deployment offers, and nothing
    # is configured in test, so a row has to be conjured for it to render.
    setup do
      configured = [client_id: "id", client_secret: "secret"]

      for provider <- [:github, :hex] do
        original = Application.fetch_env(:varsel, provider)

        Application.put_env(
          :varsel,
          provider,
          if(provider == :hex,
            do: Keyword.put(configured, :base_url, "https://hex.pm"),
            else: configured
          )
        )

        on_exit(fn ->
          case original do
            {:ok, value} -> Application.put_env(:varsel, provider, value)
            :error -> Application.delete_env(:varsel, provider)
          end
        end)
      end

      :ok
    end

    test "drops the identity", %{conn: conn} do
      user = register_user("alice")
      link_hex_identity(user, "alice_hex", "alice@hex.example")

      {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/account")

      hex = Enum.find(identities(user), &(to_string(&1.strategy) == "hex"))

      html =
        lv
        |> element(~s{button[phx-value-identity_id="#{hex.id}"]})
        |> render_click()

      assert html =~ "Unlinked Hex.pm"
      assert Enum.map(identities(user), &to_string(&1.strategy)) == ["github"]
    end

    test "refuses the only provider left, which would lock the account out" do
      user = register_user("alice")

      assert [only] = identities(user)

      assert {:error, _error} = Accounts.unlink_provider(only, actor: user)
      assert length(identities(user)) == 1
    end

    test "offers no unlink button when there is only one provider", %{conn: conn} do
      user = register_user("alice")

      {:ok, _lv, html} = conn |> log_in(user) |> live(~p"/settings/account")

      refute html =~ "Unlink"
    end

    test "nobody unlinks someone else's provider" do
      alice = register_user("alice")
      poc = register_user("poc", :poc)
      link_hex_identity(alice, "alice_hex", "alice@hex.example")

      hex = Enum.find(identities(alice), &(to_string(&1.strategy) == "hex"))

      assert {:error, %Forbidden{}} = Accounts.unlink_provider(hex, actor: poc)
      assert length(identities(alice)) == 2
    end
  end

  describe "deleting your own account" do
    test "deletes it and lands somewhere public", %{conn: conn} do
      user = register_user("alice")

      {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/account")

      assert {:error, {:live_redirect, %{to: "/"}}} =
               lv |> element("button[phx-click=delete_account]") |> render_click()

      assert {:error, %Ash.Error.Invalid{}} = Ash.get(User, user.id, authorize?: false)
    end

    # The session cookie outlives the account, so what stops it being useful
    # is the token revocation rather than anything the page does.
    test "leaves the session unable to authenticate", %{conn: conn} do
      user = register_user("alice")

      {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/account")
      lv |> element("button[phx-click=delete_account]") |> render_click()

      assert %{rows: [["revocation"]]} =
               Varsel.Repo.query!("SELECT purpose FROM tokens WHERE subject = $1", [
                 "user?id=#{user.id}"
               ])
    end
  end

  describe "sessions" do
    # A stored sign-in token is what a session *is*, so making one directly is
    # the same thing the browser ends up with.
    defp sign_in_session(user, details \\ nil) do
      context = if details, do: %{shared: %{sign_in_details: details}}, else: %{}
      {:ok, _token, claims} = AshAuthentication.Jwt.token_for_user(user, %{}, context: context)
      claims["jti"]
    end

    defp session_purposes(user) do
      %{rows: rows} =
        Varsel.Repo.query!("SELECT jti, purpose FROM tokens WHERE subject = $1", [
          "user?id=#{user.id}"
        ])

      Map.new(rows, fn [jti, purpose] -> {jti, purpose} end)
    end

    test "lists the sessions signed in on the account", %{conn: conn} do
      user = register_user("alice")

      sign_in_session(user, %{
        "user_agent" => "Mozilla/5.0 (Macintosh) Chrome/141",
        "ip" => "198.51.100.4"
      })

      {:ok, _lv, html} = conn |> log_in(user) |> live(~p"/settings/account")

      assert html =~ "Chrome on macOS"
      assert html =~ "198.51.100.4"
    end

    # Sessions predating the recording, or made by a client that sends no user
    # agent, still have to render as something.
    test "says so when there is nothing recorded about a session", %{conn: conn} do
      user = register_user("alice")
      sign_in_session(user)

      {:ok, _lv, html} = conn |> log_in(user) |> live(~p"/settings/account")

      assert html =~ "Unknown browser"
    end

    test "signing out a session revokes that token alone", %{conn: conn} do
      user = register_user("alice")
      one = sign_in_session(user)
      two = sign_in_session(user)

      {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/account")

      lv |> element(~s{button[phx-value-jti="#{one}"]}) |> render_click()

      purposes = session_purposes(user)
      assert purposes[one] == "revocation"
      assert purposes[two] == "user"
    end

    test "signing out everywhere else leaves the current session alone", %{conn: conn} do
      user = register_user("alice")
      current = sign_in_session(user)
      other = sign_in_session(user)

      {:ok, lv, _html} =
        conn
        |> log_in(user)
        |> Plug.Test.init_test_session(%{"current_session_jti" => current})
        |> live(~p"/settings/account")

      lv |> element("button[phx-click=revoke_other_sessions]") |> render_click()

      purposes = session_purposes(user)
      assert purposes[other] == "revocation"
      assert purposes[current] == "user"
    end

    # The row for the session you are reading from has no button, so this can
    # only arrive hand-made — and must not sign you out sideways.
    test "refuses to sign out the session making the request", %{conn: conn} do
      user = register_user("alice")
      current = sign_in_session(user)

      {:ok, lv, _html} =
        conn
        |> log_in(user)
        |> Plug.Test.init_test_session(%{"current_session_jti" => current})
        |> live(~p"/settings/account")

      render_click(lv, "revoke_session", %{"jti" => current})

      assert session_purposes(user)[current] == "user"
    end

    test "a session belonging to somebody else is not listed", %{conn: conn} do
      user = register_user("alice")
      stranger = register_user("mallory")
      theirs = sign_in_session(stranger)

      {:ok, _lv, html} = conn |> log_in(user) |> live(~p"/settings/account")

      refute html =~ theirs
    end
  end
end
