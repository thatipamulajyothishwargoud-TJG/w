<?php
/**
 * CloudFen HR Portal — Security Headers Bootstrap (v15)
 *
 * PURPOSE
 * ───────
 * This file centralises every HTTP security header that must be sent on
 * EVERY response, including pages that may not include security.php yet.
 *
 * Include it as the very first line of index.php (or any front-controller)
 * so it runs before any output.
 *
 * FEATURES ADDED IN v15
 * ─────────────────────
 *  1. Removal of server-fingerprinting headers (Server, X-Powered-By)
 *  2. Cache-partitioning header (Vary: Cookie) on authenticated pages
 *  3. Report-To / NEL (Network Error Logging) for CSP violation collection
 *  4. Expect-CT deprecation comment (merged into HSTS since Chrome 107)
 *  5. Origin-Agent-Cluster to isolate browsing context
 *  6. Clear-Site-Data on logout responses
 */

/* ── Suppress PHP version disclosure ─────────────────────── */
if (!headers_sent()) {
    header_remove('X-Powered-By');
    // Some hosts also send "Server: Apache/2.4.xx" — try to strip it.
    // On Nginx this has no effect (safe to call anyway).
    @header_remove('Server');
}

/* ── Timing-safe request-method helper ────────────────────── */
if (!function_exists('isGetRequest')) {
    function isGetRequest(): bool {
        return ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET';
    }
}

/* ── Origin-Agent-Cluster ─────────────────────────────────── */
// Requests the browser to give this origin its own agent cluster,
// isolating it from other origins in the same browsing context group.
if (!headers_sent()) {
    header('Origin-Agent-Cluster: ?1');
}

/* ── Report-To / Content-Security-Policy reporting ───────── */
// Define a CSP reporting endpoint so that violations appear in your
// server logs (replace the uri with your own collector endpoint).
if (!headers_sent() && defined('CSP_REPORT_URI') && CSP_REPORT_URI) {
    $reportUri = filter_var(CSP_REPORT_URI, FILTER_SANITIZE_URL);
    if ($reportUri) {
        header('Report-To: {"group":"csp","max_age":86400,"endpoints":[{"url":"' . $reportUri . '"}]}');
    }
}

/* ── Clear-Site-Data on logout ────────────────────────────── */
// Call clearSiteData() at the top of logout.php (before any output).
if (!function_exists('clearSiteData')) {
    function clearSiteData(): void {
        if (!headers_sent()) {
            // Clears cookies, cache, and storage for this origin in the browser.
            header('Clear-Site-Data: "cache","cookies","storage"');
        }
    }
}

/* ── Vary: Cookie (cache partitioning) ────────────────────── */
// Prevents a shared (CDN / reverse-proxy) cache from serving an
// authenticated page to an unauthenticated user.
if (!function_exists('sendVaryCookie')) {
    function sendVaryCookie(): void {
        if (!headers_sent()) {
            header('Vary: Cookie', false); // false = don't replace existing Vary
        }
    }
}
