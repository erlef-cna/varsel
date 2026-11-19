<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

# Contributing

## Development

The development environment is managed with [devenv](https://devenv.sh/) as a
Nix flake:

```shell
nix develop --no-pure-eval
devenv up        # starts PostgreSQL
mix setup        # installs dependencies, creates and migrates the database
mix phx.server
```

The application is then available at [`localhost:4000`](http://localhost:4000).
Run `mix precommit` before committing; it formats, lints and runs the test
suite.

Signing in creates an account with no role. To give yourself the POC role,
open [AshAdmin](http://localhost:4000/dev/admin), find your user and set
`role` to `poc`. From an `iex -S mix phx.server` session instead:

```elixir
Varsel.Accounts.User
|> Ash.get!("<user-id>", authorize?: false)
|> Ash.update!(%{role: :poc}, action: :set_role, authorize?: false)
```

## Releasing

A pushed `v*` tag deploys to production. To prepare a release, run this from
a clean `main` inside the devenv shell:

```shell
mix cut_release 0.12.0
```

The task sets the version in `mix.exs`, `assets/package.json` and the plugin
manifests in `.claude-plugin/`. It shows the diff and asks for confirmation.
Then it updates `assets/package-lock.json`, commits `Release v0.12.0` and
creates the signed tag `v0.12.0`.

The task does not push. Examine the commit and the tag, then push both:

```shell
git push --follow-tags
```

To see the diff without a change, add `--dry-run`.

The task is only available in the `dev` and `test` environments.
