# Netlify URL with the full PHP/MySQL application

The Netlify site is the public URL and reverse-proxies requests to the PHP application. PHP, database-backed login, HR operations, and uploads run on the backend host. This keeps the existing application server-rendered and functional; Netlify does not receive or publish the PHP source files.

## 1. Deploy the PHP backend

Use the same GitHub repository and `main` branch to create the backend web service. The root `Dockerfile` is configured for PHP 8.3 + Apache and binds to the service's injected `PORT`. Create a MySQL service, attach persistent storage for both MySQL data and uploads, and add the backend environment variables from [`DEPLOY_RAILWAY.md`](DEPLOY_RAILWAY.md). Keep the database private. Generate the backend's HTTPS public domain.

The backend needs `APP_URL` set to the Netlify public URL so redirects, password-reset links, and secure session cookies use the visitor-facing HTTPS origin. Set it after Netlify creates the site domain, then redeploy the backend.

## 2. Connect the GitHub repository to Netlify

Create a Netlify site from `thatipamulajyothishwargoud-TJG/w`, branch `main`, with the repository root as the base directory. The committed [`netlify.toml`](netlify.toml) uses `node tools/netlify-build.mjs` and publishes only the generated `netlify-dist` directory. Do not set a static `index.php` publish directory.

Before the first successful build, add this Netlify environment variable:

| Variable | Value |
| --- | --- |
| `CLOUDFEN_BACKEND_ORIGIN` | The backend's HTTPS origin only, such as `https://your-service.example.com` |

The build checks that this value is a valid HTTPS origin, then writes Netlify proxy rules for `/` and every other path. PHP routes, static assets, form submissions, session cookies, query strings, and uploads therefore use the same Netlify host in the browser. The proxy forwards the entire request to the PHP service; no PHP pages are built as static HTML.

After Netlify assigns the site's `*.netlify.app` domain, copy that exact HTTPS URL to the backend's `APP_URL` variable and redeploy the backend. Add SMTP settings to the backend if email verification, invitations, or password resets need to send email.

## 3. Check the finished site

Open the Netlify domain and check `/healthz.php`; it should return `ok` only when the backend can reach MySQL. Test Administrator, HR Manager, and Employee sign-in, verify the right dashboard appears for each role, then test a database write and document upload. Check the Netlify deploy log and backend runtime log if any request fails.

Netlify's external proxy rewrites have a 26-second response timeout, so long-running server work must be redesigned as an asynchronous task. See Netlify's [proxy rewrite documentation](https://docs.netlify.com/manage/routing/redirects/rewrites-proxies/) and [environment-variable configuration](https://docs.netlify.com/build/configure-builds/file-based-configuration/). The backend provider separately charges for PHP compute, MySQL, and persistent storage; review its current plan before enabling services.
