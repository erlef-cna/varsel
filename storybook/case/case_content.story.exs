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
          solutions: "Upgrade to OTP 27.3.4.13 or 28.5.0.2.",
          technical_analysis:
            "**1. Path handling.** `ssh_sftpd:resolve_path/2` joins the client path onto " <>
              "the root without normalising `..` segments.\n\n**2. Oracle.** The error " <>
              "for a missing file differs from the one for a forbidden path.",
          proof_of_concept:
            "1. Connect with any SFTP client as an authenticated user.\n" <>
              "2. Request `stat` on `../../etc/passwd`.\n" <>
              "3. Compare the error with the one for `../../does-not-exist`."
        }
      },
      %Variation{
        id: :internal_notes,
        description: "Team-only notes, collapsed and marked as never reaching the record.",
        attributes: %{
          description: "A path-existence oracle in the SFTP daemon.",
          internal_notes: "Waiting on the reporter to confirm the **28.x** backport before we request review."
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
