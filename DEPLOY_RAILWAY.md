# Full-stack deployment on Railway

CloudFen is a PHP 8.3 + Apache + MySQL application. Deploy the repository as a Docker web service and keep the database and employee uploads on persistent volumes. Do not deploy this project as a static site.

## 1. Create the database service

In Railway, create a project and add the MySQL template. Name the service `MySQL` so the variable references below match. Attach or verify a persistent volume mounted at `/var/lib/mysql`. Railway's MySQL service exposes connection variables such as `MYSQLHOST`, `MYSQLPORT`, `MYSQLUSER`, `MYSQLPASSWORD`, and `MYSQLDATABASE`.

## 2. Add the web service

Connect the GitHub repository `thatipamulajyothishwargoud-TJG/w` on the `main` branch. Keep the root directory at `/`. Railway detects the root `Dockerfile`; do not set a static publish directory or a custom start command. The container entrypoint binds Apache to Railway's injected `PORT`.

Configure these variables on the web service. Use Railway reference variables for the MySQL values so the database credentials stay in the platform:

| Variable | Value |
| --- | --- |
| `APP_NAME` | `CloudFen HR Workspace` |
| `APP_URL` | The HTTPS domain generated for the web service, after generating it |
| `APP_TIMEZONE` | `Asia/Kolkata` |
| `APP_DEMO_MODE` | `true` to initialize the fictional demo profiles and demo sign-ins |
| `DB_HOST` | `${{MySQL.MYSQLHOST}}` |
| `DB_PORT` | `${{MySQL.MYSQLPORT}}` |
| `DB_NAME` | `${{MySQL.MYSQLDATABASE}}` |
| `DB_USER` | `${{MySQL.MYSQLUSER}}` |
| `DB_PASS` | `${{MySQL.MYSQLPASSWORD}}` |
| `JWT_SECRET` | A private random value of at least 32 characters |
| `UPLOAD_BASE_PATH` | `/var/data/cloudfen/uploads` |
| `SETUP_ADMIN_EMAIL` | Your administrator email |
| `SETUP_ADMIN_NAME` | `Workspace Administrator` |
| `SETUP_ADMIN_PASSWORD` | A private password at least 14 characters long |
| `DEMO_ACCOUNT_PASSWORD` | A private password at least 14 characters long for fictional demo accounts |

Create random secrets in a password manager and enter them only in Railway's Variables UI. Do not commit them or paste them into chat. The startup script initializes missing schema and demo rows without resetting existing data.

Add a persistent volume to the web service mounted at `/var/data/cloudfen` for employee uploads. Generate the web service's public domain, set `APP_URL` to that HTTPS URL, and set the health-check path to `/healthz.php`.

## 3. Configure email

Email verification, invitations, and password reset require an SMTP provider. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_ENCRYPTION`, `MAIL_FROM`, and `MAIL_FROM_NAME` in Railway's Variables UI. Use an SMTP or app-specific credential; never use or publish your mailbox's normal password.

## 4. Verify after deployment

Wait for the database and web service to report healthy. The initial administrator signs in with `SETUP_ADMIN_EMAIL` and `SETUP_ADMIN_PASSWORD`. With demo mode enabled, the fictional role accounts are `demo.admin@example.invalid` (Administrator), `demo.hr@example.invalid` (HR Manager), and `demo.ava.bennett@example.invalid` (Employee); all use `DEMO_ACCOUNT_PASSWORD`. Use the matching role-specific sign-in portal. These `.invalid` addresses are intentionally non-deliverable and only work as seeded demo logins.

Verify each login and dashboard, then test one write action (such as a leave request) and a document upload before sharing the URL. Check Railway's deployment and runtime logs if any check fails.

Railway supports Dockerfile builds, MySQL services, and persistent volumes; review current plan and resource pricing before provisioning because usage can exceed the subscription's included amount. See [Dockerfiles](https://docs.railway.com/builds/dockerfiles), [MySQL](https://docs.railway.com/databases/mysql), [Volumes](https://docs.railway.com/volumes), and [Pricing](https://docs.railway.com/pricing).
