# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Types.CVSSTest do
  use ExUnit.Case, async: true

  alias CveManagement.Types.CVSS
  alias Phoenix.HTML.Safe

  @v3_vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  @v4_vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

  describe "cast_input/2" do
    test "parses a v3.1 vector string" do
      assert {:ok, %CVSS{version: :v3, score: 9.8, severity: :critical, vector: @v3_vector}} =
               CVSS.cast_input(@v3_vector, [])
    end

    test "parses a v4.0 vector string" do
      assert {:ok, %CVSS{version: :v4}} = CVSS.cast_input(@v4_vector, [])
    end

    test "accepts an already-cast struct" do
      {:ok, cvss} = CVSS.cast_input(@v3_vector, [])
      assert {:ok, ^cvss} = CVSS.cast_input(cvss, [])
    end

    test "accepts a parsed erlang record tuple" do
      {:ok, parsed} = :cvss.parse(@v3_vector)
      assert {:ok, %CVSS{version: :v3}} = CVSS.cast_input(parsed, [])
    end

    test "returns error for invalid vector" do
      assert {:error, _} = CVSS.cast_input("not-a-vector", [])
    end

    test "returns nil for nil" do
      assert {:ok, nil} = CVSS.cast_input(nil, [])
    end
  end

  describe "apply_constraints/2" do
    test "passes when version is allowed" do
      {:ok, cvss} = CVSS.cast_input(@v3_vector, [])
      assert {:ok, _} = CVSS.apply_constraints(cvss, version: [:v3, :v4])
    end

    test "rejects when version is not allowed" do
      {:ok, cvss} = CVSS.cast_input(@v3_vector, [])
      assert {:error, _} = CVSS.apply_constraints(cvss, version: [:v4])
    end

    test "passes with no version constraint" do
      {:ok, cvss} = CVSS.cast_input(@v3_vector, [])
      assert {:ok, _} = CVSS.apply_constraints(cvss, [])
    end
  end

  describe "dump_to_native/2 and cast_stored/2 roundtrip" do
    test "roundtrips v3 vector through storage" do
      {:ok, cvss} = CVSS.cast_input(@v3_vector, [])
      {:ok, native} = CVSS.dump_to_native(cvss, [])

      assert native["vector"] == @v3_vector
      assert native["version"] == "v3"
      assert is_number(native["score"])
      assert is_binary(native["severity"])

      {:ok, restored} = CVSS.cast_stored(native, [])
      assert restored.vector == cvss.vector
      assert restored.version == cvss.version
      assert restored.score == cvss.score
      assert restored.severity == cvss.severity
    end
  end

  describe "Phoenix.HTML.Safe" do
    test "renders the vector string" do
      {:ok, cvss} = CVSS.cast_input(@v3_vector, [])
      assert Safe.to_iodata(cvss) == @v3_vector
    end
  end
end
