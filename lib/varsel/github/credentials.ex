# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Credentials do
  @moduledoc """
  Which GitHub credential a request runs with. Every module that calls
  GitHub on someone's behalf asks here.

  A request about a repository (an advisory read or write, a report, the
  admin and private-reporting checks, the owners and team members of the
  repository's organization) runs with the actor's own App user token when
  their login reaches the App's installation on that repository. The synced
  rows of `Varsel.GitHub` say which installation covers the repository and
  which logins reach it.

  An actor who may act as the App (`Varsel.GitHub.can_installation_token?`)
  has one more credential: the installation token of the repository. Such
  an actor without a GitHub identity, or whose login does not reach the
  installation, acts with it. Such an actor whose own token does not renew
  acts with it too. Such an actor whose login reaches it and whose request
  GitHub answers with 404 or 403 runs the request once more with it.
  That retry is the one place a second credential follows a failure.
  Everyone else has their own token or nothing.

  A request about no particular repository (the global advisory database, a
  profile lookup, the OTP versions table) runs with
  `Varsel.GitHub.public_read_token/0`. When the App is not configured, the
  profile lookup and the OTP versions table run anonymously
  (`public_read_or_anonymous/0`). Nothing else runs anonymously.
  """

  alias Varsel.Accounts.User
  alias Varsel.GitHub
  alias Varsel.GitHub.App
  alias Varsel.GitHub.Errors.NotInstalled
  alias Varsel.GitHub.Installation
  alias Varsel.GitHub.UserToken

  @typedoc """
  A credential: whose token it is and the token. `:user` is the actor's own
  App user token, `:installation` the installation token of the repository
  asked about, `:public_read` the token of `Varsel.GitHub.public_read_token/0`.
  """
  @type t :: %{kind: :user | :installation | :public_read, token: String.t()}

  @typedoc """
  Why there is no credential:

  - `UserToken.reason()`: the actor has no GitHub identity, or their own
    token did not renew.
  - `:not_reachable`: the actor may not act as the App, and their login does
    not reach an installation of the App on the repository.
  - `:not_installed`: the actor may act as the App, and the App is not
    installed on the repository.
  - `:not_configured`: the request needs the home organization's
    installation, and there is none.
  - `:github_unreachable`: GitHub did not mint an installation token.
  """
  @type reason ::
          UserToken.reason()
          | :not_reachable
          | :not_installed
          | :not_configured
          | :github_unreachable

  @typedoc """
  What the actor can do on a repository, known before any request:
  `:user` and `:installation` name the credential a request starts with.
  Any `reason()` means no request is made.
  """
  @type reach :: :user | :installation | reason()

  @doc """
  The credential a request about `owner/repo` starts with, as `reach/3`
  decides it.
  """
  @spec repository(User.t() | nil, String.t(), String.t()) :: {:ok, t()} | {:error, reason()}
  def repository(actor, owner, repo) do
    case plan(actor, owner, repo) do
      {:user, token, _installation, _app?} -> {:ok, %{kind: :user, token: token}}
      {:installation, installation} -> installation_credential(installation, actor)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "What `actor` can do on `owner/repo`, for a page to decide what to offer."
  @spec reach(User.t() | nil, String.t(), String.t()) :: reach()
  def reach(actor, owner, repo) do
    case plan(actor, owner, repo) do
      {:user, _token, _installation, _app?} -> :user
      {:installation, _installation} -> :installation
      {:error, reason} -> reason
    end
  end

  @doc "Whether a request can start from `reach`."
  @spec acts?(reach() | :public_read | nil) :: boolean()
  def acts?(reach), do: reach in [:user, :installation, :public_read]

  @doc """
  Whether `actor` may try a request before its repository is known, as a
  pasted advisory URL is: a person with a GitHub identity, or an actor who
  may act as the App.
  """
  @spec may_try?(User.t() | nil) :: boolean()
  def may_try?(actor), do: UserToken.linked?(actor) or app?(actor)

  @doc """
  Runs `fun` with the credential for `owner/repo` and answers
  `{kind, result}`, or `{:no_credential, reason}` when there is none.

  For an actor who may act as the App and who started with their own token,
  a `result` of `:not_found` or `{:error, {:http, 403, _body}}` runs `fun`
  once more with the installation token. `answer:` picks that GitHub answer
  out of a result of another shape.
  """
  @spec run(User.t() | nil, String.t(), String.t(), (t() -> result), keyword()) ::
          {:user | :installation, result} | {:no_credential, reason()}
        when result: term()
  def run(actor, owner, repo, fun, opts \\ []) do
    answer = Keyword.get(opts, :answer, & &1)

    case plan(actor, owner, repo) do
      {:user, token, installation, app?} ->
        result = fun.(%{kind: :user, token: token})

        if app? and retry?(answer.(result)),
          do: retry(installation, actor, fun, result),
          else: {:user, result}

      {:installation, installation} ->
        case installation_credential(installation, actor) do
          {:ok, credential} -> {:installation, fun.(credential)}
          {:error, reason} -> {:no_credential, reason}
        end

      {:error, reason} ->
        {:no_credential, reason}
    end
  end

  @doc "The credential of `Varsel.GitHub.public_read_token/0`."
  @spec public_read() :: {:ok, t()} | {:error, :not_configured | :github_unreachable}
  def public_read do
    case GitHub.public_read_token() do
      {:ok, token} -> {:ok, %{kind: :public_read, token: token}}
      {:error, error} -> {:error, public_read_reason(error)}
    end
  end

  @doc """
  The token of `public_read/0`, or nil when the App is not configured. Only
  the profile lookup and the OTP versions table take nil.
  """
  @spec public_read_or_anonymous() ::
          {:ok, String.t() | nil} | {:error, :not_configured | :github_unreachable}
  def public_read_or_anonymous do
    if App.configured?() do
      with {:ok, %{token: token}} <- public_read(), do: {:ok, token}
    else
      {:ok, nil}
    end
  end

  @doc """
  The sentence an action states, after its subject, when there is no
  credential for it.
  """
  @spec message(reason()) :: String.t()
  def message(:not_reachable),
    do: "is on a repository your GitHub login cannot act on. The repository's owner needs to install the EEF CNA app"

  def message(:not_installed), do: "cannot be done from here: the EEF CNA app is not installed on the repository"

  def message(:not_configured), do: "cannot be read from GitHub here: the EEF CNA app is not set up"

  def message(:github_unreachable), do: "could not reach GitHub"
  def message(reason), do: UserToken.message(reason)

  defp plan(nil, _owner, _repo), do: {:error, :no_github_identity}

  defp plan(%User{} = actor, owner, repo) do
    installation =
      GitHub.installation_for_repository!(owner, repo, actor: actor, load: [:reached_by_actor?])

    decide(actor, installation, app?(actor))
  end

  defp decide(_actor, nil, true), do: {:error, :not_installed}

  defp decide(actor, nil, false),
    do: {:error, if(UserToken.linked?(actor), do: :not_reachable, else: :no_github_identity)}

  defp decide(actor, %Installation{reached_by_actor?: true} = installation, app?) do
    case UserToken.fetch(actor) do
      {:ok, token} -> {:user, token, installation, app?}
      {:error, _reason} when app? -> {:installation, installation}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decide(_actor, %Installation{} = installation, true), do: {:installation, installation}

  defp decide(_actor, %Installation{}, false), do: {:error, :not_reachable}

  defp app?(nil), do: false
  defp app?(actor), do: GitHub.can_installation_token?(actor, nil)

  defp installation_credential(installation, actor) do
    case GitHub.installation_token(installation.id, actor: actor) do
      {:ok, token} -> {:ok, %{kind: :installation, token: token}}
      {:error, _error} -> {:error, :github_unreachable}
    end
  end

  defp retry(installation, actor, fun, first) do
    case installation_credential(installation, actor) do
      {:ok, credential} -> {:installation, fun.(credential)}
      {:error, _reason} -> {:user, first}
    end
  end

  defp retry?(:not_found), do: true
  defp retry?({:error, {:http, 403, _body}}), do: true
  defp retry?(_answer), do: false

  defp public_read_reason(%NotInstalled{}), do: :not_configured

  defp public_read_reason(%{errors: errors}) when is_list(errors) do
    if Enum.any?(errors, &match?(%NotInstalled{}, &1)),
      do: :not_configured,
      else: :github_unreachable
  end

  defp public_read_reason(_error), do: :github_unreachable
end
