# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackageRepoUrlTest do
  use Varsel.DataCase, async: true

  alias Varsel.Cases
  alias Varsel.Fixtures

  setup do
    poc = Fixtures.register_user("repo_url_poc", :poc)
    case_record = Fixtures.open_case(poc)
    %{poc: poc, case: case_record}
  end

  defp add(case_record, poc, url) do
    Cases.add_affected_package(
      %{case_id: case_record.id, vendor: "acme", product: "lib", repo_url: url},
      actor: poc
    )
  end

  describe "repo_url validation" do
    test "accepts https to a public host", %{poc: poc, case: case_record} do
      # Public IP literals need no DNS; a public forge name resolves normally.
      for url <- [
            "https://github.com/acme/lib",
            "https://140.82.121.3/acme/lib",
            "https://user:pass@github.com/acme/lib"
          ] do
        pkg = Fixtures.add_affected_package(poc, case_record, repo_url: url)
        assert pkg.repo_url == url
      end
    end

    test "rejects file:// and plaintext http://", %{poc: poc, case: case_record} do
      for url <- ["file:///etc/passwd", "http://github.com/x", "ftp://host/x"] do
        assert {:error, error} = add(case_record, poc, url)
        assert Exception.message(error) =~ "https"
      end
    end

    test "rejects hosts that resolve to a private/internal address", %{
      poc: poc,
      case: case_record
    } do
      for url <- [
            "https://127.0.0.1/x",
            "https://10.0.0.5/x",
            "https://192.168.1.1/x",
            "https://169.254.169.254/x",
            "https://[::1]/x",
            # `localhost` resolves offline via the hosts file to loopback.
            "https://localhost/x"
          ] do
        assert {:error, error} = add(case_record, poc, url)
        assert Exception.message(error) =~ "public host"
      end
    end

    test "rejects a bad repo_url on edit too", %{poc: poc, case: case_record} do
      pkg = Fixtures.add_affected_package(poc, case_record)

      assert {:error, e1} =
               Cases.edit_affected_package(pkg, %{repo_url: "file:///etc/shadow"}, actor: poc)

      assert Exception.message(e1) =~ "https"

      assert {:error, e2} =
               Cases.edit_affected_package(pkg, %{repo_url: "https://10.1.2.3/x"}, actor: poc)

      assert Exception.message(e2) =~ "public host"
    end
  end
end
