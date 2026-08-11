# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ProgramFile do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AffectedComponents.program_file/1

  def layout, do: :one_column

  def description, do: "An affected source file and what it contributes."

  def variations do
    [
      %Variation{
        id: :path_only,
        description: "A file listed on its own — the path is what a reader matches their tree against.",
        attributes: %{path: "lib/ash_authentication_phoenix/controller.ex"}
      },
      %Variation{
        id: :with_modules,
        attributes: %{
          path: "lib/absinthe/federation/schema/entities_field.ex",
          modules: ["Absinthe.Federation.Schema.EntitiesField"]
        }
      },
      %Variation{
        id: :with_routines,
        description: "Long Erlang and Rust names break rather than forcing the card wide.",
        attributes: %{
          path: "lib/ssh/src/ssh_xfer.erl",
          modules: ["ssh_xfer"],
          routines: ["ssh_xfer:xf_request/3", "ssh_xfer:handle_ctrl_result/2"]
        }
      },
      %Variation{
        id: :rust,
        attributes: %{
          path: "src/tokenizer/charref.rs",
          modules: ["html5ever::tokenizer::char_ref"],
          routines: ["CharRefTokenizer::do_named", "CharRefTokenizer::unconsume_numeric"]
        }
      }
    ]
  end
end
