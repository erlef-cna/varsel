# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackagePresetTest do
  use Varsel.DataCase, async: true

  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Fixtures

  @intro_sha String.duplicate("a", 40)
  @fix_sha String.duplicate("b", 40)
  @fix_backport_sha String.duplicate("c", 40)

  setup do
    poc = Fixtures.register_user("preset_poc", :poc)
    case_record = Fixtures.open_case(poc)
    %{poc: poc, case: case_record}
  end

  describe "add_otp" do
    test "creates the prefilled package with one otp channel per application and boundary facts",
         %{poc: poc, case: case_record} do
      package =
        Cases.add_otp_affected_package!(
          %{
            case_id: case_record.id,
            applications: ["ssh", "ssl"],
            introduced_commit: @intro_sha,
            fixed_commits: [@fix_sha, @fix_backport_sha],
            program_files: [
              %{
                path: "lib/ssh/src/ssh_sftpd.erl",
                modules: ["ssh_sftpd"],
                routines: ["ssh_sftpd:handle_op/4"]
              }
            ]
          },
          actor: poc,
          load: [:channels, :version_events]
        )

      assert package.vendor == "Erlang"
      assert package.product == "OTP"
      assert package.repo_url == "https://github.com/erlang/otp"
      assert package.cpe == ~S(cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*)

      assert [
               %{
                 path: "lib/ssh/src/ssh_sftpd.erl",
                 modules: ["ssh_sftpd"],
                 routines: ["ssh_sftpd:handle_op/4"]
               }
             ] = package.program_files

      assert [
               %{purl_type: :otp, name: "ssh", subpath: "lib/ssh", position: 0},
               %{purl_type: :otp, name: "ssl", subpath: "lib/ssl", position: 1}
             ] = package.channels

      assert MapSet.new(package.version_events, &{&1.event, &1.commit_sha}) ==
               MapSet.new([
                 {:introduced, @intro_sha},
                 {:fixed, @fix_sha},
                 {:fixed, @fix_backport_sha}
               ])

      assert Enum.all?(package.version_events, &is_nil(&1.package_channel_id))
    end

    test "requires at least one application", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{}} =
               Cases.add_otp_affected_package(
                 %{case_id: case_record.id, applications: [], introduced_commit: @intro_sha},
                 actor: poc
               )
    end

    test "rejects malformed commit SHAs", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{}} =
               Cases.add_otp_affected_package(
                 %{case_id: case_record.id, applications: ["ssh"], introduced_commit: "abc123"},
                 actor: poc
               )

      assert {:error, %Invalid{}} =
               Cases.add_otp_affected_package(
                 %{case_id: case_record.id, applications: ["ssh"], fixed_commits: ["OTP-27.0"]},
                 actor: poc
               )
    end

    test "commits are optional at creation time", %{poc: poc, case: case_record} do
      package =
        Cases.add_otp_affected_package!(
          %{case_id: case_record.id, applications: ["stdlib"]},
          actor: poc,
          load: [:channels, :version_events]
        )

      assert [%{name: "stdlib", subpath: "lib/stdlib"}] = package.channels
      assert package.version_events == []
    end

    test "erts lives at the repository root, not under lib/", %{poc: poc, case: case_record} do
      package =
        Cases.add_otp_affected_package!(
          %{case_id: case_record.id, applications: ["erts"]},
          actor: poc,
          load: [:channels]
        )

      assert [%{name: "erts", subpath: "erts"}] = package.channels
    end

    test "an assigned supporter may use it, an unassigned one may not",
         %{poc: poc, case: case_record} do
      assigned = Fixtures.register_user("preset_assigned", :supporter)
      unassigned = Fixtures.register_user("preset_unassigned", :supporter)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: assigned.id}, actor: poc)

      assert %AffectedPackage{} =
               Cases.add_otp_affected_package!(
                 %{case_id: case_record.id, applications: ["ssh"]},
                 actor: assigned
               )

      assert {:error, %Ash.Error.Forbidden{}} =
               Cases.add_otp_affected_package(
                 %{case_id: case_record.id, applications: ["ssh"]},
                 actor: unassigned
               )
    end
  end

  describe "add_elixir" do
    test "creates the prefilled package with otp channels for the Elixir applications",
         %{poc: poc, case: case_record} do
      package =
        Cases.add_elixir_affected_package!(
          %{
            case_id: case_record.id,
            applications: ["elixir"],
            introduced_commit: @intro_sha,
            fixed_commits: [@fix_sha],
            program_files: [%{path: "lib/elixir/lib/version.ex", modules: ["'Elixir.Version'"]}]
          },
          actor: poc,
          load: [:channels, :version_events]
        )

      assert package.vendor == "elixir-lang"
      assert package.product == "elixir"
      assert package.repo_url == "https://github.com/elixir-lang/elixir"
      # The default vendor/product CPE derivation matches the published records.
      assert package.cpe == nil

      assert [%{purl_type: :otp, name: "elixir", subpath: "lib/elixir"}] = package.channels
      assert length(package.version_events) == 2
    end
  end

  describe "add_gleam" do
    test "creates the prefilled package with the sid and OCI channels",
         %{poc: poc, case: case_record} do
      package =
        Cases.add_gleam_affected_package!(
          %{
            case_id: case_record.id,
            introduced_commit: @intro_sha,
            fixed_commits: [@fix_sha],
            program_files: [%{path: "compiler-core/src/docs.rs", modules: ["compiler-core"]}]
          },
          actor: poc,
          load: [:channels, :version_events]
        )

      assert package.vendor == "Gleam"
      assert package.product == "Gleam"
      assert package.repo_url == "https://github.com/gleam-lang/gleam"
      assert package.cpe == "cpe:2.3:a:gleam-lang:gleam:*:*:*:*:*:*:*:*"

      assert [sid, oci] = package.channels
      assert %{purl_type: :sid, namespace: "gleam.run", name: "gleam"} = sid
      assert %{purl_type: :oci, name: "gleam"} = oci
      assert oci.qualifiers == %{"repository_url" => "ghcr.io/gleam-lang"}
      assert "erlang" in oci.tag_suffixes and "scratch" in oci.tag_suffixes

      assert length(package.version_events) == 2
    end
  end

  describe "preset :insert proposals" do
    test "propose and accept creates the prefilled package with its children",
         %{poc: poc, case: case_record} do
      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :affected_package,
            operation: :insert,
            proposed_value: %{
              "value" => %{
                "preset" => "otp",
                "applications" => ["ssh"],
                "introduced_commit" => @intro_sha,
                "fixed_commits" => [@fix_sha],
                "program_files" => [
                  %{"path" => "lib/ssh/src/ssh_sftpd.erl", "modules" => ["ssh_sftpd"]}
                ]
              }
            }
          },
          actor: poc
        )

      accepted = Cases.accept_case_proposal!(proposal, %{}, actor: poc)
      assert accepted.state == :accepted

      package =
        Ash.get!(AffectedPackage, accepted.applied_target_id,
          authorize?: false,
          load: [:channels, :version_events]
        )

      assert package.vendor == "Erlang"
      assert package.product == "OTP"

      assert [%{path: "lib/ssh/src/ssh_sftpd.erl", modules: ["ssh_sftpd"]}] =
               package.program_files

      assert [%{purl_type: :otp, name: "ssh"}] = package.channels

      assert MapSet.new(package.version_events, &{&1.event, &1.commit_sha}) ==
               MapSet.new([{:introduced, @intro_sha}, {:fixed, @fix_sha}])
    end

    test "a gleam preset proposal needs no applications", %{poc: poc, case: case_record} do
      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :affected_package,
            operation: :insert,
            proposed_value: %{"value" => %{"preset" => "gleam", "fixed_commits" => [@fix_sha]}}
          },
          actor: poc
        )

      accepted = Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      package =
        Ash.get!(AffectedPackage, accepted.applied_target_id,
          authorize?: false,
          load: [:channels]
        )

      assert package.vendor == "Gleam"
      assert [%{purl_type: :sid}, %{purl_type: :oci}] = package.channels
    end

    test "an unknown preset is rejected at propose time", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{} = error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :affected_package,
                   operation: :insert,
                   proposed_value: %{"value" => %{"preset" => "rust"}}
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "unknown preset"
    end

    test "an otp preset proposal without applications is rejected", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{} = error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :affected_package,
                   operation: :insert,
                   proposed_value: %{"value" => %{"preset" => "otp"}}
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "requires applications"
    end

    test "malformed commits and unknown payload keys are rejected", %{poc: poc, case: case_record} do
      base = %{case_id: case_record.id, target: :affected_package, operation: :insert}

      assert {:error, %Invalid{}} =
               Cases.create_case_proposal(
                 Map.put(base, :proposed_value, %{
                   "value" => %{
                     "preset" => "otp",
                     "applications" => ["ssh"],
                     "introduced_commit" => "not-a-sha"
                   }
                 }),
                 actor: poc
               )

      assert {:error, %Invalid{}} =
               Cases.create_case_proposal(
                 Map.put(base, :proposed_value, %{
                   "value" => %{
                     "preset" => "otp",
                     "applications" => ["ssh"],
                     "vendor" => "Someone else"
                   }
                 }),
                 actor: poc
               )
    end

    test "a preset payload may only target affected_package", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{} = error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :reference,
                   operation: :insert,
                   proposed_value: %{"value" => %{"preset" => "otp", "applications" => ["ssh"]}}
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "only target affected_package"
    end
  end
end
