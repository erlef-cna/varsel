# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.FieldList do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.DisclosureComponents.field_list/1

  def layout, do: :one_column

  def description, do: "An object's small print, as label and value."

  def variations do
    [
      %Variation{
        id: :default,
        attributes: %{
          rows: [
            {"cpe", "cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*"}
          ]
        }
      },
      %Variation{
        id: :blanks_dropped,
        description:
          "Rows with nothing to say are dropped, so a caller can list every field it might " <>
            "show without guarding each one.",
        attributes: %{
          rows: [
            {"vendor", "Erlang"},
            {"platforms", []},
            {"cpe", nil},
            {"product", "OTP"}
          ]
        }
      },
      %Variation{
        id: :prose,
        description:
          "A value that reads as words rather than an identifier drops the mono face, " <>
            "per row — a list usually mixes the two.",
        attributes: %{
          rows: [
            {"cpe", "cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*"}
          ]
        }
      },
      %Variation{
        id: :long_value,
        description: "A long identifier breaks inside its column instead of widening the card.",
        attributes: %{
          rows: [
            {"purl", "pkg:generic/acme_lib?vcs_url=git%2Bhttps:%2F%2Fgit.example.com%2Fteam%2Facme_lib"}
          ]
        }
      }
    ]
  end
end
