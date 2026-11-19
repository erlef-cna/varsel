<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

# Contributing

The [Development](README.md#development) section of the README tells you how
to set up the environment. Run `mix precommit` before you commit.

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
