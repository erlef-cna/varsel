# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Validations.RepoUrlHttps do
  @moduledoc """
  Requires an `AffectedPackage`'s `repo_url` to be an `https://` URL that
  resolves to a public host.

  Derivation hands `repo_url` to `Exgit.clone/2`, which dispatches on the URL:
  a `file://` URL reads the server's local filesystem and a plaintext
  `http://` URL fetches over an unencrypted connection to any host. Neither
  has a legitimate use here — a source repository is an https forge
  (github.com, a self-hosted GitLab, …) — so both are rejected.

  Arbitrary *public* https hosts stay allowed on purpose (self-hosted forges
  are a feature), but a host that resolves only to a private / non-routable
  address (loopback, RFC 1918, link-local, …) is rejected, so a case editor
  cannot aim server-side egress at an internal service. See
  `Varsel.Net.PrivateAddress` and THREAT_MODEL.md §9.

  The scheme is checked by parsing with `URI.new/1`, not by matching the
  string, so casing, credentials, and stray whitespace can't slip a non-https
  URL past a prefix check.
  """

  use Ash.Resource.Validation

  alias Varsel.Net.PrivateAddress

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    case Ash.Changeset.fetch_change(changeset, :repo_url) do
      {:ok, repo_url} when is_binary(repo_url) ->
        check(repo_url)

      # nil (cleared) or not changing — nothing to check.
      _not_changing_to_a_string ->
        :ok
    end
  end

  defp check(repo_url) do
    # Parse and check the scheme rather than string-matching a prefix, so
    # casing (`HTTPS://`) and credentials can't slip a non-https URL past.
    # Ash's :string type has already trimmed surrounding whitespace and
    # mapped "" to nil before this runs.
    case URI.new(repo_url) do
      {:ok, %URI{scheme: "https", host: host}} when is_binary(host) and host != "" ->
        check_public(host)

      _otherwise ->
        {:error, field: :repo_url, message: "must be an https:// URL"}
    end
  end

  defp check_public(host) do
    if PrivateAddress.private_host?(host) do
      {:error, field: :repo_url, message: "must resolve to a public host (private/internal addresses are not allowed)"}
    else
      :ok
    end
  end
end
