defmodule Varsel.Repo.Migrations.ReshapePackageChannels do
  @moduledoc """
  Reshapes `case_package_channels` around the package/service split.

  Schema: adds `kind`, `domain` and `version_type`, and lets `purl_type` be
  null (a service has no purl), widening the uniqueness identity to cover
  `domain` with non-distinct nulls.

  Data, in the same transaction:

    * `purl_type = 'hosted'` was the old stand-in for "no purl at all". Those
      rows become `kind = 'service'`, moving what named the service into
      `domain` (the old rows carried it in `name`, which a service must not
      set) and pinning `version_type = 'date'`, which is all a service could
      ever derive.
    * Every other row keeps its purl type and is stamped with the
      `version_type` its type used to imply *positionally* — `sid` meant OTP
      releases only on the erlang/otp repository, and `otp` applications
      version in semver everywhere except there, both of which the old code
      decided from the package's repo_url at render time. Writing it down is
      the point of the column.
    * Each package with a `repo_url` gains the repository's own channel, which
      the renderer used to conjure implicitly. github/bitbucket repositories
      get their registered purl type; anything else becomes `pkg:generic`
      carrying `vcs_url`.
    * `derivation_cache` loses its top-level `"git"` key: those versions now
      belong to the repository channel's entry under `"channels"`. Rather than
      re-key it (the new channel's id would have to be threaded in), the cache
      is simply marked stale by clearing `derivation_cached_at`, which is what
      it is: `refresh_derivation` recomputes it, and the preview blocks on the
      staleness until it does.

  Paper-trail versions are deliberately left untouched: they are an audit log
  of what the rows *were*, and rewriting history to look like the new shape
  would be a lie about what happened.
  """

  use Ecto.Migration

  # The erlang/otp repository, the one place `sid`/`otp` channels meant OTP
  # release versioning rather than semver (Elixir's applications are `pkg:otp`
  # too, and version with Elixir).
  @otp_repo "https://github.com/erlang/otp"

  def up do
    alter table(:case_package_channels) do
      add :kind, :text, null: false, default: "package"
      add :domain, :text
      add :version_type, :text
    end

    drop_if_exists unique_index(
                     :case_package_channels,
                     [:affected_package_id, :purl_type, :namespace, :name],
                     name: "case_package_channels_unique_channel_index"
                   )

    alter table(:case_package_channels) do
      modify :purl_type, :text, null: true
    end

    create unique_index(
             :case_package_channels,
             [:affected_package_id, :purl_type, :namespace, :name, :domain],
             name: "case_package_channels_unique_channel_index",
             nulls_distinct: false
           )

    migrate_hosted_channels()
    backfill_version_types()
    insert_repository_channels()
    stale_derivation_caches()
  end

  def down do
    # The repository channels this migration inserted are indistinguishable
    # from hand-authored ones by then, so they are left in place: dropping the
    # columns below already returns the table to its old shape, and the old
    # renderer conjured its git entry regardless of what rows existed.
    execute("""
    UPDATE case_package_channels
    SET purl_type = 'hosted', name = COALESCE(name, domain)
    WHERE kind = 'service'
    """)

    execute("UPDATE case_affected_packages SET derivation_cached_at = NULL")

    drop_if_exists unique_index(
                     :case_package_channels,
                     [:affected_package_id, :purl_type, :namespace, :name, :domain],
                     name: "case_package_channels_unique_channel_index"
                   )

    alter table(:case_package_channels) do
      modify :purl_type, :text, null: false
    end

    create unique_index(
             :case_package_channels,
             [:affected_package_id, :purl_type, :namespace, :name],
             name: "case_package_channels_unique_channel_index"
           )

    alter table(:case_package_channels) do
      remove :version_type
      remove :domain
      remove :kind
    end
  end

  # The old `:hosted` purl type named the service in `name`; a service channel
  # names it in `domain` and carries none of the purl fields.
  defp migrate_hosted_channels do
    execute("""
    UPDATE case_package_channels
    SET kind = 'service',
        domain = COALESCE(domain, name),
        version_type = 'date',
        purl_type = NULL,
        namespace = NULL,
        name = NULL,
        subpath = NULL,
        qualifiers = '{}'::jsonb
    WHERE purl_type = 'hosted'
    """)
  end

  # What each purl type used to imply, including the repo-dependent OTP cases
  # the renderer decided at run time.
  defp backfill_version_types do
    execute("""
    UPDATE case_package_channels channel
    SET version_type = CASE
      WHEN channel.purl_type IN ('sid', 'otp') AND package.repo_url = '#{@otp_repo}' THEN 'otp'
      WHEN channel.purl_type = 'oci' THEN 'other'
      ELSE 'semver'
    END
    FROM case_affected_packages package
    WHERE package.id = channel.affected_package_id
      AND channel.kind = 'package'
      AND channel.version_type IS NULL
    """)
  end

  # The repository channel every package with a repo_url used to get for free.
  # Position 1000 matches AddRepositoryChannel: far past any authored channel,
  # so the repository closes the entries the way the published records read.
  # Only github and bitbucket have registered purl types; every other forge is
  # `generic` with its URL in the vcs_url qualifier.
  defp insert_repository_channels do
    execute("""
    INSERT INTO case_package_channels
      (id, case_id, affected_package_id, kind, purl_type, namespace, name,
       qualifiers, version_type, tag_suffixes, position, inserted_at, updated_at)
    SELECT
      gen_random_uuid(),
      package.case_id,
      package.id,
      'package',
      repo.purl_type,
      repo.namespace,
      repo.name,
      CASE WHEN repo.purl_type = 'generic'
           THEN jsonb_build_object('vcs_url', 'git+' || package.repo_url)
           ELSE '{}'::jsonb END,
      'git',
      ARRAY[]::text[],
      1000,
      now(),
      now()
    FROM case_affected_packages package
    CROSS JOIN LATERAL (
      SELECT
        CASE host.name
          WHEN 'github.com' THEN 'github'
          WHEN 'bitbucket.org' THEN 'bitbucket'
          ELSE 'generic'
        END AS purl_type,
        CASE
          WHEN host.name IN ('github.com', 'bitbucket.org')
            THEN array_to_string(path.segments[1:array_length(path.segments, 1) - 1], '/')
          ELSE NULL
        END AS namespace,
        path.segments[array_length(path.segments, 1)] AS name
      FROM (SELECT split_part(regexp_replace(package.repo_url, '^https?://', ''), '/', 1) AS name) host
      CROSS JOIN LATERAL (
        SELECT string_to_array(
          trim(both '/' from regexp_replace(
            regexp_replace(package.repo_url, '^https?://[^/]+', ''), '\\.git/?$', '')),
          '/') AS segments
      ) path
    ) repo
    WHERE package.repo_url IS NOT NULL
      AND array_length(
            string_to_array(
              trim(both '/' from regexp_replace(
                regexp_replace(package.repo_url, '^https?://[^/]+', ''), '\\.git/?$', '')),
              '/'),
            1) >= 1
    """)
  end

  # The cached derivations key their git ranges under a top-level "git" that no
  # longer exists. Clearing the timestamp marks them stale rather than
  # rewriting them: refresh_derivation recomputes the whole thing, and the
  # preview refuses to publish a stale cache in the meantime.
  defp stale_derivation_caches do
    execute("UPDATE case_affected_packages SET derivation_cached_at = NULL")
  end
end
