# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.ChannelInput do
  @moduledoc """
  A channel authored inline as part of a `propose_affected_package` insert, so
  a package and its distribution channels are one proposal (and one accept)
  rather than a package proposal followed by channel proposals that must wait
  for it to be accepted before they have a parent to reference.

  The fields mirror `Varsel.Cases.PackageChannel`'s proposable payload minus
  `position` (ordering follows the array). Typing it as an embedded resource
  (rather than a bare map) validates each nested channel at propose time. The
  override escape hatches are intentionally not authorable inline — add them
  with `propose_package_channel` once the package is accepted.
  """

  use Ash.Resource,
    data_layer: :embedded,
    extensions: [AshGraphql.Resource]

  alias Varsel.Cases.PackageChannel.Kind
  alias Varsel.Cases.PackageChannel.Validations.ConsistentIdentity
  alias Varsel.Cases.PackageChannel.VersionType

  graphql do
    type :case_channel_input
  end

  validations do
    validate ConsistentIdentity
  end

  attributes do
    attribute :kind, Kind do
      description "Whether this channel distributes a package (purl) or is a running service (domain, date-versioned)."
      allow_nil? false
      default :package
      public? true
    end

    attribute :purl_type, :string do
      description """
      Package URL type of this distribution channel, e.g. "hex", "otp", "oci",
      "sid", "npm". Any purl type works. List the distribution channels only —
      the source repository's own channel is derived from the package's
      repo_url, so you normally don't add it here (do so only for something
      like a second forge host).
      """

      constraints match: ~r{^[a-z0-9][a-z0-9._-]*$}
      public? true
    end

    attribute :namespace, :string do
      description ~s{The purl namespace, e.g. "gleam.run" (sid) or an npm scope. Nil for unnamespaced ecosystems like hex.}
      public? true
    end

    attribute :name, :string do
      description ~s{The purl name, e.g. "ash_authentication_phoenix" (hex), "stdlib" (otp). Required for package channels.}
      public? true
    end

    attribute :domain, :string do
      description ~s{The domain a service channel answers on, e.g. "hex.pm". Set instead of the purl fields, and only on service channels.}
      public? true
    end

    attribute :qualifiers, :map do
      description ~S(Purl qualifiers rendered into the packageURL, e.g. %{"repository_url" => "ghcr.io/gleam-lang"} for oci.)
      allow_nil? false
      default %{}
      public? true
    end

    attribute :subpath, :string do
      description ~s{Repository-root-relative directory this channel distributes, e.g. "lib/ssh" for pkg:otp/ssh. Nil distributes the whole repository.}
      public? true
    end

    attribute :version_type, VersionType do
      description "Vocabulary of the derived version bounds. Nil takes the purl type's default (hex/npm semver, otp otp, oci other)."
      public? true
    end

    attribute :tag_prefix, :string do
      description ~s{String prepended to every derived version, e.g. "v" for v1.2.3 tags. Nil or empty for bare versions.}
      public? true
    end

    attribute :tag_suffixes, {:array, :string} do
      description ~s{Flavor suffixes appended to every derived version (e.g. ["elixir", "erlang"]); the derived range repeats once per flavor. A "-" entry is the bare version, e.g. ["-", "special"] for 1.2.3 and 1.2.3-special.}
      allow_nil? false
      default []
      public? true
    end
  end
end
