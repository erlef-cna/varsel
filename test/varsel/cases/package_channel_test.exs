# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannelTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Fixtures

  require Ash.Query

  setup do
    poc = Fixtures.register_user("channel_poc", :poc)
    case_record = Fixtures.open_case(poc)
    package = Fixtures.add_affected_package(poc, case_record)

    %{poc: poc, case: case_record, package: package}
  end

  defp add_channel(poc, package, attrs) do
    Cases.add_package_channel!(
      Map.merge(
        %{case_id: package.case_id, affected_package_id: package.id},
        attrs
      ),
      actor: poc
    )
  end

  describe "the purl calculation" do
    test "composes the stored parts", %{poc: poc, package: package} do
      channel = add_channel(poc, package, %{purl_type: "hex", name: "acme_lib"})

      assert Ash.load!(channel, :purl, authorize?: false).purl == "pkg:hex/acme_lib"
    end

    test "includes namespace and qualifiers", %{poc: poc, package: package} do
      channel =
        add_channel(poc, package, %{
          purl_type: "oci",
          namespace: "gleam.run",
          name: "gleam",
          qualifiers: %{"repository_url" => "ghcr.io/gleam-lang"}
        })

      purl = Ash.load!(channel, :purl, authorize?: false).purl

      assert purl =~ "pkg:oci/gleam.run/gleam"
      assert purl =~ "repository_url=ghcr.io"
    end

    test "any purl type composes, known or not", %{poc: poc, package: package} do
      channel = add_channel(poc, package, %{purl_type: "cargo", name: "acme"})

      assert Ash.load!(channel, :purl, authorize?: false).purl == "pkg:cargo/acme"
    end

    test "a service has no purl", %{poc: poc, package: package} do
      channel = add_channel(poc, package, %{kind: :service, domain: "hex.pm"})

      assert Ash.load!(channel, :purl, authorize?: false).purl == nil
    end
  end

  describe "identity validation" do
    test "a package channel needs a purl type and a name", %{poc: poc, package: package} do
      assert {:error, _} =
               Cases.add_package_channel(
                 %{
                   case_id: package.case_id,
                   affected_package_id: package.id,
                   purl_type: "hex"
                 },
                 actor: poc
               )

      assert {:error, _} =
               Cases.add_package_channel(
                 %{
                   case_id: package.case_id,
                   affected_package_id: package.id,
                   name: "acme_lib"
                 },
                 actor: poc
               )
    end

    test "a service needs a domain and rejects the purl fields", %{poc: poc, package: package} do
      assert {:error, _} =
               Cases.add_package_channel(
                 %{
                   case_id: package.case_id,
                   affected_package_id: package.id,
                   kind: :service
                 },
                 actor: poc
               )

      assert {:error, _} =
               Cases.add_package_channel(
                 %{
                   case_id: package.case_id,
                   affected_package_id: package.id,
                   kind: :service,
                   domain: "hex.pm",
                   purl_type: "hex"
                 },
                 actor: poc
               )
    end

    test "a purl type must be spellable as one", %{poc: poc, package: package} do
      assert {:error, _} =
               Cases.add_package_channel(
                 %{
                   case_id: package.case_id,
                   affected_package_id: package.id,
                   purl_type: "pkg:hex",
                   name: "acme_lib"
                 },
                 actor: poc
               )
    end

    test "a purl type is normalized on the way in", %{poc: poc, package: package} do
      channel = add_channel(poc, package, %{purl_type: " Hex ", name: "acme_lib"})

      assert channel.purl_type == "hex"
      assert Ash.load!(channel, :purl, authorize?: false).purl == "pkg:hex/acme_lib"
    end
  end

  describe "derivation_state" do
    defp state(package) do
      Ash.load!(package, :derivation_state, authorize?: false).derivation_state
    end

    defp derive(package) do
      package
      |> Ash.Changeset.for_update(:store_derivation, %{derivation_cache: %{}}, authorize?: false)
      |> Ash.update!()
    end

    # Backdates the whole product — its row, its channels and its facts — as if
    # the derivation had run `hours` ago and nothing had happened since. Moving
    # only the package would leave its channels newer, which is genuinely
    # `:outdated` rather than aged.
    defp age(package, hours) do
      at = DateTime.shift(DateTime.utc_now(), hour: -hours)
      package = derive(package)

      for table <- ["case_package_channels", "case_version_events"] do
        Varsel.Repo.query!(
          "UPDATE #{table} SET updated_at = $1 WHERE affected_package_id = $2",
          [at, Ecto.UUID.dump!(package.id)]
        )
      end

      Varsel.Repo.query!(
        "UPDATE case_affected_packages SET updated_at = $1, derivation_cached_at = $1 WHERE id = $2",
        [at, Ecto.UUID.dump!(package.id)]
      )

      Ash.reload!(package, authorize?: false)
    end

    test "a product that has never derived", %{package: package} do
      assert state(package) == :never
    end

    test "a product derived after its last change", %{package: package} do
      assert package |> derive() |> state() == :current
    end

    test "a product whose channels changed after it derived", %{poc: poc, package: package} do
      package = derive(package)

      add_channel(poc, package, %{purl_type: "hex", name: "acme_lib"})

      assert state(package) == :outdated
    end

    test "a product whose boundary facts changed after it derived", %{
      poc: poc,
      case: case_record,
      package: package
    } do
      package = derive(package)

      Cases.add_version_event!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          event: :introduced,
          commit_sha: String.duplicate("a", 40)
        },
        actor: poc
      )

      assert state(package) == :outdated
    end

    test "a current derivation ages", %{package: package} do
      assert package |> age(48) |> state() == :ageing
    end

    # The point of an expression: the state narrows a query, not just a render.
    test "filters in the database", %{package: package} do
      age(package, 48)

      assert [_ageing] =
               AffectedPackage
               |> Ash.Query.filter(derivation_state == :ageing)
               |> Ash.read!(authorize?: false)

      assert [] =
               AffectedPackage
               |> Ash.Query.filter(derivation_state == :outdated)
               |> Ash.read!(authorize?: false)
    end
  end

  describe "the repository channel" do
    test "is created with the package", %{package: package} do
      assert [%{purl_type: "github", namespace: "acme", name: "acme_lib", version_type: :git}] =
               Ash.load!(package, :channels, authorize?: false).channels
    end

    test "sorts after channels added later", %{poc: poc, package: package} do
      add_channel(poc, package, %{purl_type: "hex", name: "acme_lib", position: 0})

      assert [%{purl_type: "hex"}, %{purl_type: "github"}] =
               Ash.load!(package, :channels, authorize?: false).channels
    end

    test "is not created for a package without a repository", %{poc: poc, case: case_record} do
      package =
        Fixtures.add_affected_package(poc, case_record, %{repo_url: nil, product: "service_only"})

      assert [] = Ash.load!(package, :channels, authorize?: false).channels
    end

    # Storybook builds preset forms while the module compiles, before the purl
    # registry exists, so identifying the repository has to wait for the action
    # to run rather than happening as the changeset is assembled.
    test "is not resolved while a changeset is merely being built", %{case: case_record} do
      form =
        AffectedPackage
        |> AshPhoenix.Form.for_create(:add_gleam, as: "child")
        |> AshPhoenix.Form.validate(%{"case_id" => case_record.id})

      assert %AshPhoenix.Form{} = form
    end

    test "is an ordinary row: editable and removable", %{poc: poc, package: package} do
      [repository] = Ash.load!(package, :channels, authorize?: false).channels

      edited = Cases.edit_package_channel!(repository, %{subpath: "lib/acme"}, actor: poc)
      assert edited.subpath == "lib/acme"

      Cases.remove_package_channel!(edited, actor: poc)
      assert [] = Ash.load!(package, :channels, authorize?: false).channels
    end
  end
end
