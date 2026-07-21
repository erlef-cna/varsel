# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.ProgramFile do
  @moduledoc """
  One affected source file with the modules and routines it contributes —
  the facts behind the `programFiles` / `modules` / `programRoutines` fields
  of every rendered `affected[]` entry.

  Paths are repository-root-relative (`lib/ssh/src/ssh_sftpd.erl`). Storing
  modules and routines *per file* lets `Varsel.Cases.Render.Channel` scope an
  entry to the files under its channel's `subpath` (e.g. `lib/ssh` on
  `pkg:otp/ssh`) with the prefix stripped, while the git/forge entry keeps
  every file under its full path — matching how the published records spell
  multi-application products (see CVE-2026-48858's inets/ftp entries).
  """

  use Ash.Resource,
    data_layer: :embedded,
    extensions: [AshGraphql.Resource]

  graphql do
    type :case_program_file
  end

  attributes do
    attribute :path, :string do
      description "Repository-root-relative path of the affected file."
      allow_nil? false
      public? true
    end

    attribute :modules, {:array, :string} do
      description "Modules this file contributes (affected[].modules), e.g. [\"ssh_sftpd\"]."
      allow_nil? false
      default []
      public? true
    end

    attribute :routines, {:array, :string} do
      description """
      Routines this file contributes, in Erlang notation
      (affected[].programRoutines[].name), e.g. ["ssh_sftpd:handle_op/4"].
      """

      allow_nil? false
      default []
      public? true
    end
  end
end
