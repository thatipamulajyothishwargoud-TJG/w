# CloudFen HR Workspace

CloudFen is a PHP and MySQL HR portal with separate employee and HR/admin workflows. It includes a glassmorphism interface, animated 3D landing and sign-in scenes, and a moving pointer effect.

## What’s included

- Public landing page and sign-in flow
- Employee profiles, directory, attendance, leave requests, documents, timesheets, projects, goals, and reviews
- HR and administrator tools for people, hiring, leave policy, approvals, announcements, analytics, workforce reports, and audit history
- MySQL-backed records, role-based access checks, CSRF protection, and fictional demo profiles
- Local Three.js and other required frontend assets

## Deploy the full application to Render

The repository includes a Render Blueprint for a PHP web service, a private MySQL 8.4 service, and persistent disks for the database and employee uploads. In Render, create a new Blueprint from this repository's `main` branch. The Blueprint creates a separate `cloudfen-hrportal-v2` service and does not modify the older `cloudfen-hrportal` service.

During Blueprint setup, provide `SETUP_ADMIN_EMAIL` for the first administrator. Render generates the administrator password, demo-account password, database passwords, and JWT secret; keep those values in Render's environment settings and never copy them into GitHub. The web service initializes the schema and fictional employee/demo records when it starts. Demo credentials can be read from the service's environment settings.

The persistent disks make uploaded documents and MySQL records survive restarts and redeploys. Render charges for the two paid service instances and their disk storage; review the Blueprint's displayed monthly estimate before creating the services. If you need a no-cost preview, remove the persistent disks and use free instances only with the understanding that records and uploads can be lost when Render restarts or redeploys them.

After the Blueprint is live, open the new web service URL and sign in with the administrator email and generated password. Keep the database service private; only the PHP web service needs a public URL.

## Run on this workstation

This checkout uses the isolated local database and development credentials stored outside the repository in `C:\Users\thati\hrportal-runtime`. Open PowerShell in this folder and run:

```powershell
.\start-local.ps1
```

Then open [http://127.0.0.1:8088](http://127.0.0.1:8088). The local sign-in details are in `C:\Users\thati\hrportal-runtime\LOCAL-ACCESS.txt`; fictional demo accounts are listed in `C:\Users\thati\hrportal-runtime\DEMO-ACCOUNTS.txt`.

The script reads local database credentials from the external runtime folder, so those values are not stored in this repository.

## Set up another development environment

Use PHP 8.2 or newer with PDO MySQL enabled and a MySQL-compatible database. Copy `.env.example` to a private environment configuration and set the database values, `APP_URL`, `APP_DEMO_MODE`, and a random `JWT_SECRET` of at least 32 characters. The PHP app reads environment variables; it does not load `.env` files automatically.

For a new database, run `php tools/setup.php` from the command line. To create fictional demo sign-ins, set `APP_DEMO_MODE=true`, set `DEMO_ACCOUNT_PASSWORD` to a value of at least 14 characters, then run `php tools/seed-demo.php --local-demo --enable-logins`. To add demo project tasks, run `php tools/seed-project-board.php --local-demo`. These seed commands only create fictional demo data and preserve existing records.

For a first administrator, set `SETUP_ADMIN_EMAIL`, `SETUP_ADMIN_NAME`, and `SETUP_ADMIN_PASSWORD` (14 or more characters), then run `php tools/setup.php --admin`. Remove the temporary administrator password from the process environment afterward.

## Data and configuration

Never commit `.env` files, real employee records, uploaded documents, local database files, or production credentials. Use `.env.example` as a variable-name reference only. Uploaded employee records can contain sensitive HR data and belong in protected storage.
