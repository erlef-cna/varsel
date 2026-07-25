# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ProgramFiles do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  alias Varsel.Cases.AffectedPackage.ProgramFile

  def function, do: &VarselWeb.CaseComponents.program_files/1

  def variations do
    [
      %Variation{
        id: :default,
        description: "A path, followed by the modules and routines it contributes.",
        attributes: %{
          files: [
            %ProgramFile{
              path: "lib/ssh/src/ssh_sftpd.erl",
              modules: ["ssh_sftpd"],
              routines: ["ssh_sftpd:handle_op/4"]
            },
            %ProgramFile{
              path: "lib/ssh/src/ssh_connection.erl",
              modules: ["ssh_connection"],
              routines: []
            }
          ]
        }
      },
      %Variation{
        id: :path_only,
        description: "A file recorded as affected without naming what it contributes.",
        attributes: %{files: [%ProgramFile{path: "lib/ssh/src/ssh.erl"}]}
      },
      %Variation{
        id: :wrapping,
        description:
          "Path and chips are one text flow, so a long path and a long chip list " <>
            "wrap the same way rather than the chips being pushed off a row.",
        attributes: %{
          files: [
            %ProgramFile{
              path: "lib/inets/src/http_server/httpd_request_handler.erl",
              modules: ["httpd_request_handler", "httpd_request", "httpd_response"],
              routines: [
                "httpd_request_handler:handle_info/2",
                "httpd_request:validate_uri/1"
              ]
            }
          ]
        }
      },
      %Variation{
        id: :empty,
        description: "No files recorded yet.",
        attributes: %{files: []}
      }
    ]
  end
end
