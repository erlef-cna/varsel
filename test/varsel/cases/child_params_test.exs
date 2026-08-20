# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ChildParamsTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.ChildParams
  alias Varsel.Cases.Derivation.Emit

  doctest ChildParams

  describe "normalize/3" do
    test "merges the parent ids the form does not carry" do
      params = ChildParams.normalize("credit", %{"value" => "Alice"}, %{"case_id" => "case-1"})

      assert params["case_id"] == "case-1"
      assert params["value"] == "Alice"
    end

    test "splits the list-backed inputs of the type it is given" do
      params = ChildParams.normalize("channel", %{"tag_suffixes" => "OTP-, v"}, %{})

      assert params["tag_suffixes"] == ["OTP-", "v"]
    end

    test "leaves a field alone when the type does not list it" do
      params = ChildParams.normalize("credit", %{"tag_suffixes" => "OTP-, v"}, %{})

      assert params["tag_suffixes"] == "OTP-, v"
    end

    test "expands the since-creation checkbox to the OTP root commit" do
      params =
        ChildParams.normalize("package_otp", %{"affected_since_creation" => "true"}, %{})

      assert params["introduced_commit"] == Emit.otp_root_commit()
      refute Map.has_key?(params, "affected_since_creation")
    end

    test "unchecking since-creation clears the root commit" do
      params =
        ChildParams.normalize(
          "package_otp",
          %{"affected_since_creation" => "false", "introduced_commit" => Emit.otp_root_commit()},
          %{}
        )

      assert params["introduced_commit"] == ""
    end

    test "unchecked since-creation keeps a hand-typed commit" do
      sha = String.duplicate("a", 40)

      params =
        ChildParams.normalize(
          "package_otp",
          %{"affected_since_creation" => "false", "introduced_commit" => sha},
          %{}
        )

      assert params["introduced_commit"] == sha
    end

    test "keeps the bare-tag marker as a suffix of its own" do
      params = ChildParams.normalize("channel", %{"tag_suffixes" => "-, special"}, %{})

      assert params["tag_suffixes"] == ["-", "special"]
    end

    test "merges the reference checkbox tags with the custom ones" do
      params =
        ChildParams.normalize(
          "reference",
          %{"tags" => ["", "patch"], "custom_tags" => "x_vendor, patch"},
          %{}
        )

      assert params["tags"] == ["patch", "x_vendor"]
      refute Map.has_key?(params, "custom_tags")
    end

    test "reads the numeric id back out of a datalist label" do
      assert %{"cwe_id" => "613"} =
               ChildParams.normalize("weakness", %{"cwe_id" => "CWE-613 Insufficient"}, %{})

      assert %{"capec_id" => "63"} =
               ChildParams.normalize("impact", %{"capec_id" => "CAPEC-63 XSS"}, %{})
    end

    test "keeps a bare classification number as it is" do
      assert %{"cwe_id" => "613"} = ChildParams.normalize("weakness", %{"cwe_id" => "613"}, %{})
    end

    test "leaves a classification id alone when it holds no number" do
      assert %{"cwe_id" => "none"} = ChildParams.normalize("weakness", %{"cwe_id" => "none"}, %{})
    end

    test "reads channel qualifiers out of their key=value text" do
      params = ChildParams.normalize("channel", %{"qualifiers" => "arch=any, os = linux"}, %{})

      assert params["qualifiers"] == %{"arch" => "any", "os" => "linux"}
    end

    test "drops a qualifier that names no value" do
      params = ChildParams.normalize("channel", %{"qualifiers" => "arch=any, broken"}, %{})

      assert params["qualifiers"] == %{"arch" => "any"}
    end

    test "splits the comma separated lists inside each program file row" do
      params =
        ChildParams.normalize(
          "package",
          %{
            "program_files" => %{
              "0" => %{"path" => "lib/ssh.erl", "modules" => "ssh, ssh_sftpd", "routines" => ""}
            }
          },
          %{}
        )

      assert params["program_files"]["0"]["modules"] == ["ssh", "ssh_sftpd"]
      assert params["program_files"]["0"]["routines"] == []
    end

    test "leaves program files alone for a type that has none" do
      params = ChildParams.normalize("channel", %{"program_files" => %{}}, %{})

      assert params["program_files"] == %{}
    end
  end

  describe "program_files_list/1" do
    test "orders the rows by their form index rather than map order" do
      files =
        ChildParams.program_files_list(%{
          "10" => %{"path" => "c.erl"},
          "2" => %{"path" => "b.erl"},
          "1" => %{"path" => "a.erl"}
        })

      assert Enum.map(files, & &1["path"]) == ["a.erl", "b.erl", "c.erl"]
    end

    test "drops the just-added rows that carry no path" do
      files =
        ChildParams.program_files_list(%{
          "0" => %{"path" => "a.erl"},
          "1" => %{"path" => ""},
          "2" => %{"path" => nil}
        })

      assert [%{"path" => "a.erl"}] = files
    end

    test "defaults the lists a row omits and drops form-tracking keys" do
      assert [file] =
               ChildParams.program_files_list(%{
                 "0" => %{"path" => "a.erl", "_persistent_id" => "0"}
               })

      assert file == %{"path" => "a.erl", "modules" => [], "routines" => []}
    end
  end

  describe "split_list/1" do
    test "splits on both commas and newlines, trimming as it goes" do
      assert ChildParams.split_list("a, b\nc ,  d") == ["a", "b", "c", "d"]
    end

    test "drops the empty stretches between separators" do
      assert ChildParams.split_list(" , ,\n") == []
    end
  end
end
