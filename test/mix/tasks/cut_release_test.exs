# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.CutReleaseTest do
  use ExUnit.Case, async: true

  import Igniter.Test

  alias Mix.Tasks.CutRelease

  test "sets the version in mix.exs and in every JSON manifest" do
    [
      files: %{
        "mix.exs" => """
        defmodule Varsel.MixProject do
          use Mix.Project

          def project do
            [
              app: :varsel,
              version: "0.1.0",
              elixir: "~> 1.15"
            ]
          end
        end
        """,
        ".claude-plugin/plugin.json" => """
        {
          "name": "varsel-poc",
          "version": "0.1.0",
          "license": "Apache-2.0"
        }
        """,
        ".claude-plugin/marketplace.json" => """
        {
          "name": "varsel",
          "plugins": [
            {
              "name": "varsel-poc",
              "version": "0.1.0",
              "keywords": [
                "cve",
                "cna"
              ]
            }
          ]
        }
        """,
        "assets/package.json" => """
        {
          "name": "varsel-assets",
          "version": "0.1.0",
          "private": true
        }
        """
      }
    ]
    |> test_project()
    |> CutRelease.bump_version("0.12.0")
    |> assert_has_patch("mix.exs", """
    6 6   |      app: :varsel,
    7   - |      version: "0.1.0",
      7 + |      version: "0.12.0",
    8 8   |      elixir: "~> 1.15"
    """)
    |> assert_has_patch(".claude-plugin/plugin.json", """
    2 2   |  "name": "varsel-poc",
    3   - |  "version": "0.1.0",
      3 + |  "version": "0.12.0",
    4 4   |  "license": "Apache-2.0"
    """)
    |> assert_has_patch(".claude-plugin/marketplace.json", """
    5  5   |      "name": "varsel-poc",
    6    - |      "version": "0.1.0",
       6 + |      "version": "0.12.0",
    7  7   |      "keywords": [
    8  8   |        "cve",
    """)
    |> assert_has_patch("assets/package.json", """
    2 2   |  "name": "varsel-assets",
    3   - |  "version": "0.1.0",
      3 + |  "version": "0.12.0",
    4 4   |  "private": true
    """)
  end
end
