# Database Rollout Profiles

This runbook describes the minimum database configuration posture per environment.

## 1. Development

- `APP_ENV=development`
- sqlite may be used for local prototyping.
- Recommended local URL: `sqlite:///./security_platform.db`

## 2. Test / CI

- `APP_ENV=test`
- sqlite is acceptable for fast automated tests.
- Integration jobs may use an ephemeral PostgreSQL instance.

## 3. Staging

- `APP_ENV=staging`
- `DATABASE_URL` is required and must point to PostgreSQL (sqlite blocked by default).
- Set `DB_SSL_MODE=require`.
- Run `alembic upgrade head` before promotion tests.

## 4. Production

- `APP_ENV=production`
- `DATABASE_URL` is required and must point to a managed PostgreSQL cluster.
- Set `DB_SSL_MODE=require` and verify CA chain with platform trust policy.
- Ensure backups + PITR are enabled before app deployment.
- Run `alembic upgrade head` in a controlled release window.

## Rollout sequence

1. Provision database + credentials in secret manager.
2. Update Kubernetes secret `platform-secrets.database_url`.
3. Deploy migration job (`alembic upgrade head`).
4. Deploy backend workload with `APP_ENV` and DB env vars.
5. Verify `/api/v1/dashboard/summary` health on a seeded tenant.

## Notes

- `ALLOW_SQLITE_IN_NON_DEV=true` exists as a break-glass compatibility escape hatch and should not be used in normal staging/production operation.
- Keep `DB_POOL_RECYCLE` at or below cloud provider idle timeout.
