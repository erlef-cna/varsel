# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CvelintTest do
  use ExUnit.Case, async: true

  alias Varsel.CVE.Cvelint

  # Linting a well-formed record — the path that reaches the binary — is covered
  # by Varsel.CVE.CveValidationTest. What is left is the shapes that are
  # answered before it: a caller can send any JSON, so `cveMetadata` and
  # `assignerShortName` cannot be assumed to be an object and a string.
  describe "records rejected before linting" do
    test "a cveMetadata that is not an object" do
      for metadata <- ["a string", ["a", "list"], 42, true] do
        assert {:error, [{nil, message, "cveMetadata"}]} =
                 Cvelint.lint(%{"cveMetadata" => metadata})

        assert message =~ "must be an object"
      end
    end

    test "a missing cveMetadata" do
      assert {:error, [{nil, message, "cveMetadata"}]} = Cvelint.lint(%{})
      assert message =~ "is missing"
    end

    test "a missing, null or empty assignerShortName" do
      for metadata <- [%{}, %{"assignerShortName" => nil}, %{"assignerShortName" => ""}] do
        assert {:error, [{nil, message, "cveMetadata.assignerShortName"}]} =
                 Cvelint.lint(%{"cveMetadata" => metadata})

        assert message =~ "is missing"
      end
    end

    test "an assignerShortName of the wrong type" do
      for short_name <- [42, ["EEF"], %{"a" => 1}] do
        assert {:error, [{nil, message, "cveMetadata.assignerShortName"}]} =
                 Cvelint.lint(%{"cveMetadata" => %{"assignerShortName" => short_name}})

        assert message =~ "must be a string"
      end
    end
  end
end
