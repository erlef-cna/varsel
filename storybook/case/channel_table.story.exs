# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ChannelTable do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.channel_table/1

  def layout, do: :one_column

  def description, do: "Where a package ships, and the range derived for each channel."

  def variations do
    [
      %Variation{
        id: :at_rest,
        description:
          "The resting card: what ships where, and an implicit git row that carries " <>
            "no actions — there is no channel record behind it.",
        attributes: %{
          rows: [
            %{
              id: "chan-1",
              name: "pkg:otp/ssh",
              title: "pkg:otp/ssh@5.2.11",
              derived: "≥ 0 < 1.1.7 · ≥ 5.3 < 5.5.2.2"
            },
            %{id: nil, name: "github (implicit)", derived: "0 → 1 fix commit"}
          ],
          mode: :edit,
          marks: marks()
        }
      },
      %Variation{
        id: :with_subpath,
        description:
          "The editor asks which part of the repository a channel covers, so it " <>
            "gains a column and spells the way in as a caret.",
        attributes: %{
          rows: [
            %{
              id: "chan-1",
              name: "pkg:otp/ssh",
              title: "pkg:otp/ssh@5.2.11",
              subpath: "lib/ssh",
              derived: "≥ 0 < 1.1.7 · ≥ 5.3 < 5.5.2.2"
            },
            %{
              id: "chan-2",
              name: "pkg:hex/ssh_client",
              title: "pkg:hex/ssh_client",
              derived: "no derived range"
            },
            %{id: nil, name: "github (implicit)", derived: "≥ 0 < R13B03"}
          ],
          mode: :edit,
          marks: marks(),
          subpath?: true,
          edit_label: "▸"
        }
      },
      %Variation{
        id: :overridden,
        description: "A channel whose range was set by hand says so beside it.",
        attributes: %{
          rows: [
            %{
              id: "chan-1",
              name: "pkg:otp/ssh",
              title: "pkg:otp/ssh",
              derived: "≥ 1.0.0 < 2.0.0",
              note: "versions overridden"
            }
          ],
          mode: :edit,
          marks: marks()
        }
      },
      %Variation{
        id: :proposed,
        description: "Channels an open suggestion adds or removes offer no actions.",
        attributes: %{
          rows: [
            %{id: "chan-1", name: "pkg:otp/ssh", title: "pkg:otp/ssh", derived: "≥ 1.0.0"},
            %{id: "chan-new", name: "pkg:hex/ssh", title: "pkg:hex/ssh", derived: "≥ 2.0.0"},
            %{id: "chan-old", name: "pkg:npm/ssh", title: "pkg:npm/ssh", derived: "≥ 3.0.0"}
          ],
          mode: :propose,
          marks: %{
            phantom: MapSet.new(["chan-new"]),
            deleted: MapSet.new(["chan-old"])
          }
        }
      },
      %Variation{
        id: :view_only,
        description: "A case being read rather than worked on offers no actions at all.",
        attributes: %{
          rows: [
            %{id: "chan-1", name: "pkg:otp/ssh", title: "pkg:otp/ssh", derived: "≥ 1.0.0 < 2.0.0"}
          ],
          mode: :view,
          marks: marks()
        }
      },
      %Variation{
        id: :empty,
        description: "A package naming no channels and no repository draws nothing.",
        attributes: %{rows: [], mode: :edit, marks: marks()}
      }
    ]
  end

  defp marks, do: %{phantom: MapSet.new(), deleted: MapSet.new()}
end
