# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Cve.PackageDisplayName do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CveView.package_display_name/1

  def layout, do: :one_column

  # The component is inline, so a variation group would otherwise run its
  # examples together on one line.
  def container, do: {:div, class: "flex w-full flex-col items-start gap-1"}

  def variations do
    [
      %VariationGroup{
        id: :hex,
        description:
          "A hex package shortens only when nothing qualifies where it came from: a namespace " <>
            "or a `repository_url` means some other registry, and \"Hex /\" would name the wrong one.",
        variations: [
          %Variation{id: :plain, attributes: %{purl: "pkg:hex/plug"}},
          %Variation{id: :namespaced, attributes: %{purl: "pkg:hex/acme/private_thing"}},
          %Variation{
            id: :self_hosted,
            attributes: %{purl: "pkg:hex/thing?repository_url=https://hex.acme.internal"}
          }
        ]
      },
      %VariationGroup{
        id: :otp,
        description:
          "`pkg:otp` covers every OTP application, whoever ships it, so the repository it comes " <>
            "from is what names the ecosystem — the purl type alone cannot tell Erlang's from " <>
            "Elixir's. Two applications whose own name says too little are spelled out.",
        variations: [
          %Variation{
            id: :erlang,
            attributes: %{purl: "pkg:otp/ssh?repository_url=https://github.com/erlang/otp"}
          },
          %Variation{
            id: :elixir_itself,
            attributes: %{
              purl: "pkg:otp/elixir?repository_url=https://github.com/elixir-lang/elixir"
            }
          },
          %Variation{
            id: :elixir_application,
            attributes: %{
              purl: "pkg:otp/mix?repository_url=https://github.com/elixir-lang/elixir"
            }
          },
          %Variation{
            id: :rebar3,
            attributes: %{
              purl: "pkg:otp/rebar3?repository_url=https://github.com/erlang/rebar3.git"
            }
          },
          %Variation{
            id: :hex_mix_integration,
            attributes: %{purl: "pkg:otp/hex?repository_url=https://github.com/hexpm/hex.git"}
          },
          %Variation{
            id: :nerves_hub,
            attributes: %{
              purl: "pkg:otp/nerves_hub?repository_url=https://github.com/nerves-hub/nerves_hub_web"
            }
          },
          %Variation{
            id: :unrecognised_repository,
            attributes: %{purl: "pkg:otp/thing?repository_url=https://github.com/acme/thing"}
          }
        ]
      },
      %VariationGroup{
        id: :github,
        description:
          "The owner stays: four forks of esaml are published, and the repository name alone " <>
            "would make them identical.",
        variations: [
          %Variation{id: :otp, attributes: %{purl: "pkg:github/erlang/otp"}},
          %Variation{id: :fork_handnot2, attributes: %{purl: "pkg:github/handnot2/esaml"}},
          %Variation{id: :fork_dropbox, attributes: %{purl: "pkg:github/dropbox/esaml"}}
        ]
      },
      %VariationGroup{
        id: :oci,
        description:
          "An image name alone is not an address — any registry could host a `gleam`. The host " <>
            "names the ecosystem and its path joins the image, spelling out what you would pull.",
        variations: [
          %Variation{
            id: :ghcr,
            attributes: %{purl: "pkg:oci/gleam?repository_url=ghcr.io/gleam-lang"}
          },
          %Variation{id: :no_registry, attributes: %{purl: "pkg:oci/redis"}}
        ]
      },
      %VariationGroup{
        id: :sid,
        description:
          "A software id names a project, not a package within one, so it reads as the project " <>
            "alone. Whitelisted per purl — a domain has no general rule.",
        variations: [
          %Variation{id: :erlang, attributes: %{purl: "pkg:sid/erlang.org/otp"}},
          %Variation{id: :gleam, attributes: %{purl: "pkg:sid/gleam.run/gleam"}},
          %Variation{id: :unknown, attributes: %{purl: "pkg:sid/example.com/thing"}}
        ]
      },
      %Variation{
        id: :npm,
        description: "A registry package.",
        attributes: %{purl: "pkg:npm/phoenix"}
      },
      %Variation{
        id: :not_shortened,
        description:
          "Shortening is strictly whitelisted, and anything unmatched prints its purl untouched " <>
            "— better a long name than a wrong one.",
        attributes: %{purl: "pkg:cargo/serde"}
      },
      %Variation{
        id: :hosted_service,
        description:
          "An entry with no purl at all — a hosted service, which has no package to name. The " <>
            "caller's vendor/product is all there is to say.",
        attributes: %{purl: nil, fallback: "hexpm / hex.pm"}
      },
      %Variation{
        id: :linked,
        description:
          "`link` points at the package's registry page where it has one. The tables link; the " <>
            "home-page cards do not, since the whole card is already a link.",
        attributes: %{purl: "pkg:hex/plug", link: true}
      }
    ]
  end
end
