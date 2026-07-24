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

  alias Varsel.Cases.PackageChannel.PurlType

  graphql do
    type :case_channel_input
  end

  attributes do
    attribute :purl_type, PurlType do
      description """
      Package URL type of this distribution channel, e.g. :hex, :otp, :oci,
      :sid, :hosted. List the distribution channels only — the source repo's
      pkg:github channel is derived from the package's repo_url, so you normally
      don't add it here (do so only for something like a second forge host).
      """

      allow_nil? false
      public? true
    end

    attribute :namespace, :string do
      description ~s{The purl namespace, e.g. "gleam.run" (sid) or an npm scope. Nil for unnamespaced ecosystems like hex.}
      public? true
    end

    attribute :name, :string do
      description ~s{The purl name, e.g. "ash_authentication_phoenix" (hex), "stdlib" (otp). Nil only for :hosted channels.}
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

    attribute :tag_suffixes, {:array, :string} do
      description ~s{OCI image-tag flavor suffixes (e.g. ["elixir", "erlang"]); the derived range repeats once per flavor with the suffix appended.}
      allow_nil? false
      default []
      public? true
    end
  end
end
