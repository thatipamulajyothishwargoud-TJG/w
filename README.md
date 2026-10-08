# CloudFen HR Workspace

CloudFen is a PHP and MySQL HR portal with separate employee and HR/admin workflows. It includes a glassmorphism interface, animated 3D landing and sign-in scenes, and a moving pointer effect.

## What’s included

- Public landing page and sign-in flow
- Employee profiles, directory, attendance, leave requests, documents, timesheets, projects, goals, and reviews
- HR and administrator tools for people, hiring, leave policy, approvals, announcements, analytics, workforce reports, and audit history
- MySQL-backed records, role-based access checks, CSRF protection, and fictional demo profiles
- Local Three.js and other required frontend assets

## Separate role portals

- Employee sign-in: `/auth/employee-login.php` → `/employee/dashboard.php`
- HR Manager sign-in: `/auth/hr-login.php` → `/hr/dashboard.php`
- Administrator sign-in: `/auth/administrator-login.php` → `/admin/dashboard.php`

Each sign-in route checks the account role before creating a session. Employees see their own work, HR Managers get people operations and approvals, and Administrators keep system-wide controls. The general `/auth/login.php` page also links to all three portals.

## Deploy the full application

This app needs a PHP runtime, MySQL, and persistent storage; it is not a static site. For the requested Netlify URL, Netlify proxies the full site to the PHP/MySQL backend. Follow [`DEPLOY_NETLIFY.md`](DEPLOY_NETLIFY.md) for both parts. The backend uses this repository's root `Dockerfile`; [`DEPLOY_RAILWAY.md`](DEPLOY_RAILWAY.md) covers its MySQL variables, persistent storage, secrets, SMTP, and checks. Review backend hosting costs before provisioning services.

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
