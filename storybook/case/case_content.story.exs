# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CaseContent do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.case_content/1

  def layout, do: :one_column

  def description, do: "A case's written content, as the workspace shows it at rest."

  def variations do
    [
      %Variation{
        id: :description_only,
        description: "The common case: what the vulnerability is, and nothing more yet.",
        attributes: %{
          description:
            "`ssh_sftpd` resolves paths outside the configured root, letting an " <>
              "authenticated client learn whether a path **exists** outside its confinement."
        }
      },
      %Variation{
        id: :full,
        description: "Every section filled in, each under its own heading.",
        attributes: %{
          description: "A path-existence oracle in the SFTP daemon.",
          configurations: "Only servers with `sftpd` enabled are affected.",
          workarounds: "Disable the SFTP subsystem until the fix is applied.",
          solutions: "Upgrade to OTP 27.3.4.13 or 28.5.0.2."
        }
      },
      %Variation{
        id: :empty,
        description: "Nothing written yet — the case says so rather than showing a blank.",
        attributes: %{}
      }
    ]
  end
end
