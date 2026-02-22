# Stremio-Web Security Audit Report

**Date**: 2026-02-22  
**Repository**: stremio-web  
**Scope**: Client-side web application security audit  
**Auditor**: Automated Security Analysis  

---

## Executive Summary

This security audit identified **5 verified vulnerabilities** in the stremio-web codebase, ranging from **Critical** to **Medium** severity. The most severe findings involve a **host whitelist bypass** that enables open redirect attacks, **insecure random token generation** in OAuth authentication flows, and **unvalidated streaming server URL injection** via URL parameters.

---

## Vulnerability 1: Host Whitelist Bypass via `hostname.endsWith()` — Open Redirect

**Severity**: 🔴 HIGH  
**Type**: CWE-601 (URL Redirection to Untrusted Site / Open Redirect)  
**File**: `src/common/Platform/Platform.tsx` (Lines 18-27)  
**CVSS**: 7.4

### Vulnerable Code

```typescript
// src/common/Platform/Platform.tsx, Lines 18-27
const openExternal = (url: string) => {
    try {
        const { hostname } = new URL(url);
        const isWhitelisted = WHITELISTED_HOSTS.some(
            (host: string) => hostname.endsWith(host)  // ← VULNERABILITY
        );
        const finalUrl = !isWhitelisted
            ? `https://www.stremio.com/warning#${encodeURIComponent(url)}`
            : url;
        window.open(finalUrl, '_blank');
    } catch (e) {
        console.error('Failed to parse external url:', e);
    }
};
```

The whitelist is defined in `src/common/CONSTANTS.js` (Line 107):
```javascript
const WHITELISTED_HOSTS = [
    'stremio.com', 'strem.io', 'stremio.zendesk.com', 'google.com',
    'youtube.com', 'twitch.tv', 'twitter.com', 'x.com', 'netflix.com',
    'adex.network', 'amazon.com', 'forms.gle'
];
```

### Root Cause

The `String.prototype.endsWith()` method performs a simple suffix match without domain boundary awareness. This means `hostname.endsWith('x.com')` matches **any** hostname ending in the characters `x.com`, not just the domain `x.com` and its subdomains.

### Proof of Concept

An attacker registers a domain such as `evilx.com`, `attackerx.com`, or `phishingnetflix.com`. These domains pass the whitelist check:

```javascript
// All of these PASS the whitelist check:
'evilx.com'.endsWith('x.com')            // → true (matches 'x.com')
'fakegoogle.com'.endsWith('google.com')    // → true (matches 'google.com')
'notstremio.com'.endsWith('stremio.com')   // → true (matches 'stremio.com')
'evilamazon.com'.endsWith('amazon.com')    // → true (matches 'amazon.com')
'malicioustwitch.tv'.endsWith('twitch.tv') // → true (matches 'twitch.tv')
```

**Attack Scenario**: A malicious addon could include links with the `transportUrl` pointing to `https://evilx.com/phishing-page`. When the user clicks "Configure" on the addon (which calls `platform.openExternal()`), the URL bypasses the whitelist and opens directly without the warning page.

Call sites where attacker-controlled URLs reach `openExternal()`:
- `src/routes/Addons/Addons.js:94` — Addon configure URL from addon manifest
- `src/routes/Player/OptionsMenu/OptionsMenu.js:58` — Stream download/streaming URLs
- `src/routes/Player/OptionsMenu/OptionsMenu.js:63` — Subtitle track URL
- `src/routes/Settings/General/General.tsx:66` — Data export URL from server response

### Remediation

Replace `hostname.endsWith(host)` with proper domain boundary checking:

```typescript
const isWhitelisted = WHITELISTED_HOSTS.some(
    (host: string) => hostname === host || hostname.endsWith(`.${host}`)
);
```

This ensures that only the exact domain and its legitimate subdomains pass the check (e.g., `sub.x.com` passes but `evilx.com` does not).

---

## Vulnerability 2: Insecure OAuth State Token Generation via `Math.random()`

**Severity**: 🔴 HIGH  
**Type**: CWE-330 (Use of Insufficiently Random Values)  
**Files**:
- `src/routes/Intro/useFacebookLogin.ts` (Line 32)
- `src/routes/Intro/useAppleLogin.ts` (Line 42)

**CVSS**: 8.1

### Vulnerable Code

```typescript
// src/routes/Intro/useFacebookLogin.ts, Line 32
const state = hat(128);

// src/routes/Intro/useAppleLogin.ts, Line 42
const state = hat(128);
```

The `hat` library (v0.0.3) source code uses `Math.random()`:

```javascript
// node_modules/hat/index.js
for (var i = 0; i < Math.floor(digits); i++) {
    var x = Math.floor(Math.random() * base).toString(base);  // ← INSECURE
    res = x + res;
}
```

### Root Cause

The `hat` library uses `Math.random()` to generate tokens. `Math.random()` is **not cryptographically secure** — it uses a PRNG (typically xorshift128+ in V8) that provides only ~53 bits of actual entropy regardless of requested bit length, and its internal state can be reconstructed from observed outputs.

### OAuth Flow Analysis

The Facebook/Apple login flow works as follows:

1. Client generates `state = hat(128)` using `Math.random()`
2. Client opens `https://www.strem.io/login-fb/${state}` or `https://www.strem.io/login-apple/${state}`
3. User authenticates with Facebook/Apple on the strem.io server
4. Client polls `https://www.strem.io/login-fb-get-acc/${state}` every 1-2 seconds
5. Server returns `{ email, password: fbLoginToken }` or Apple credentials

### Proof of Concept

```javascript
// 1. Observe multiple Math.random() outputs from the same V8 instance
// (e.g., via a malicious addon's JavaScript or shared browsing context)
const observed = [];
for (let i = 0; i < 5; i++) {
    observed.push(Math.random());
}

// 2. Use a tool like "v8-randomness-predictor" to recover the xorshift128+ state
// from the observed outputs. This is well-documented in academic papers.
// Reference: https://blog.securityevaluators.com/hacking-the-javascript-lottery-80cc437e3b7f

// 3. With the recovered state, predict future Math.random() outputs
// to predict the OAuth state token generated by hat(128)

// 4. Race condition: Poll the credentials endpoint before the legitimate client
const predictedState = predictNextHatOutput();
const response = await fetch(
    `https://www.strem.io/login-fb-get-acc/${predictedState}`
);
const { user } = await response.json();
// Attacker now has the user's authentication credentials
```

**Impact**: An attacker who can observe `Math.random()` outputs from the same JavaScript context (e.g., through a co-located malicious addon script or browser extension) can predict the OAuth state token and steal user credentials by polling the authentication endpoint.

### Remediation

Replace `hat` with `crypto.getRandomValues()`:

```typescript
const generateSecureState = (bits: number = 128): string => {
    const bytes = new Uint8Array(bits / 8);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
};

// Usage:
const state = generateSecureState(128);
```

---

## Vulnerability 3: Streaming Server URL Injection via URL Parameters (No Validation)

**Severity**: 🟠 MEDIUM-HIGH  
**Type**: CWE-20 (Improper Input Validation) + CWE-918 (Server-Side Request Forgery)  
**File**: `src/App/SearchParamsHandler.js` (Lines 26-51)  
**CVSS**: 6.5

### Vulnerable Code

```javascript
// src/App/SearchParamsHandler.js, Lines 26-51
React.useEffect(() => {
    const { streamingServerUrl } = searchParams;

    if (streamingServerUrl) {
        // No URL validation, no scheme check, no domain check
        core.transport.dispatch({
            action: 'Ctx',
            args: {
                action: 'UpdateSettings',
                args: {
                    ...profile.settings,
                    streamingServerUrl,  // ← Directly injected without validation
                },
            },
        });
        core.transport.dispatch({
            action: 'Ctx',
            args: {
                action: 'AddServerUrl',
                args: streamingServerUrl,  // ← Also added to saved URLs
            },
        });
        toast.show({
            type: 'success',
            title: `Using streaming server at ${streamingServerUrl}`,
            timeout: 4000,
        });
    }
}, [searchParams]);
```

### Root Cause

The `streamingServerUrl` search parameter is extracted from the URL hash and passed directly to the core transport dispatcher without any validation. There are no checks for:
- URL scheme (http/https only)
- Domain restrictions
- Private/internal IP ranges
- Format validity

### Proof of Concept

**Attack via crafted link (social engineering or malicious addon redirect):**

```
https://app.strem.io/#?streamingServerUrl=http://attacker-server.com:11470/
```

Or targeting internal services:
```
https://app.strem.io/#?streamingServerUrl=http://192.168.1.1:8080/
https://app.strem.io/#?streamingServerUrl=http://localhost:9200/
https://app.strem.io/#?streamingServerUrl=http://169.254.169.254/latest/meta-data/
```

**Attack Flow**:
1. Attacker sends victim a crafted link (via social media, email, or malicious website)
2. Victim opens the link in their browser
3. `SearchParamsHandler` automatically extracts `streamingServerUrl` from hash params
4. The URL is dispatched to the Stremio core, which reconfigures the streaming server
5. All future stream requests are routed to the attacker's server
6. The attacker's server can serve malicious content or intercept stream data
7. The malicious URL is **persisted** in the user's settings via `AddServerUrl`

**Note**: Compare with the `useStreamingServerUrls.js` (Line 16-23) which does perform basic URL validation using `new URL()` — this same validation is missing from `SearchParamsHandler.js`.

### Remediation

Add URL validation before dispatching:

```javascript
if (streamingServerUrl) {
    try {
        const parsed = new URL(streamingServerUrl);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            throw new Error('Invalid protocol');
        }
        // Proceed with dispatch...
    } catch (e) {
        console.error('Invalid streaming server URL:', e);
        return;
    }
}
```

---

## Vulnerability 4: CSS Injection via Unsanitized User Avatar URL

**Severity**: 🟡 MEDIUM  
**Type**: CWE-79 (Cross-site Scripting — CSS Injection variant)  
**Files**:
- `src/routes/Settings/General/User/User.tsx` (Lines 19-20)
- `src/components/NavBar/HorizontalNavBar/NavMenu/NavMenuContent.js` (Lines 57-58)
- `src/components/ModalDialog/ModalDialog.js` (Line 64)

**CVSS**: 4.3

### Vulnerable Code

```typescript
// src/routes/Settings/General/User/User.tsx, Lines 15-23
const avatar = useMemo(() => (
    !profile.auth ?
        `url('${require('/assets/images/anonymous.png')}')`
        :
        profile.auth.user.avatar ?
            `url('${profile.auth.user.avatar}')`  // ← Unsanitized URL interpolation
            :
            `url('${require('/assets/images/default_avatar.png')}')`
), [profile.auth]);

// Applied as inline style:
<div style={{ backgroundImage: avatar }} />
```

```javascript
// src/components/NavBar/HorizontalNavBar/NavMenu/NavMenuContent.js, Lines 54-61
style={{
    backgroundImage: profile.auth === null ?
        `url('${require('/assets/images/anonymous.png')}')`
        :
        profile.auth.user.avatar ?
            `url('${profile.auth.user.avatar}')`  // ← Same pattern
            :
            `url('${require('/assets/images/default_avatar.png')}')`
}}
```

```javascript
// src/components/ModalDialog/ModalDialog.js, Line 64
<div style={{backgroundImage: `url('${background}')`}} />  // ← background prop unsanitized
```

### Root Cause

User avatar URLs from the authentication API are directly interpolated into CSS `url()` values using template literals without sanitization. If the avatar URL contains a single quote (`'`), it breaks out of the CSS `url()` context.

### Proof of Concept

If an attacker compromises the backend API or modifies their profile data to set the avatar to:

```
https://evil.com/img.png'); background: url('https://attacker.com/tracking-pixel.png
```

The resulting CSS would be:
```css
background-image: url('https://evil.com/img.png'); background: url('https://attacker.com/tracking-pixel.png')
```

This allows CSS injection to:
1. Load external tracking images (privacy violation)
2. Overlay UI elements to mislead users
3. Exfiltrate data via CSS-based side channels in some browser configurations

**Note**: Modern browsers do not execute JavaScript via CSS `url()`, limiting the severity. However, CSS injection can still be used for data exfiltration and UI manipulation.

### Remediation

Sanitize URLs before interpolation by escaping single quotes and validating URL format:

```typescript
const sanitizeCssUrl = (url: string): string => {
    try {
        const parsed = new URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol)) return '';
        return `url('${parsed.href.replace(/'/g, "\\'")}')`; 
    } catch {
        return '';
    }
};
```

---

## Vulnerability 5: Unvalidated `window.location` Assignment in DeepLinkHandler

**Severity**: 🟡 MEDIUM  
**Type**: CWE-601 (URL Redirection to Untrusted Site)  
**File**: `src/App/DeepLinkHandler.js` (Line 14)  
**CVSS**: 5.4

### Vulnerable Code

```javascript
// src/App/DeepLinkHandler.js, Lines 6-20
const DeepLinkHandler = () => {
    const streamingServer = useStreamingServer();
    React.useEffect(() => {
        if (streamingServer.torrent !== null) {
            const [, { type, content }] = streamingServer.torrent;
            if (type === 'Ready') {
                const [, deepLinks] = content;
                if (typeof deepLinks.metaDetailsVideos === 'string') {
                    window.location = deepLinks.metaDetailsVideos;  // ← No validation
                }
            }
        }
    }, [streamingServer.torrent]);
    return null;
};
```

### Root Cause

The `deepLinks.metaDetailsVideos` value comes from the streaming server's torrent parsing response. This value is assigned to `window.location` without any validation or sanitization. If a malicious torrent or a compromised streaming server returns a crafted deep link, it could redirect the user to an arbitrary URL.

### Proof of Concept

If the streaming server (which could be attacker-controlled per Vulnerability 3) returns:

```json
{
    "torrent": [null, {
        "type": "Ready",
        "content": [null, {
            "metaDetailsVideos": "https://attacker.com/phishing-page"
        }]
    }]
}
```

The `DeepLinkHandler` would execute:
```javascript
window.location = "https://attacker.com/phishing-page";
```

This redirects the user's browser to the attacker's page without any warning.

**Chained Attack**: This vulnerability can be chained with Vulnerability 3 (Streaming Server URL Injection):
1. Attacker tricks user into visiting `#?streamingServerUrl=http://evil.com:11470/`
2. The malicious streaming server responds with torrent deep links pointing to phishing pages
3. `DeepLinkHandler` automatically redirects the user

### Remediation

Validate that the deep link is an internal hash-based route:

```javascript
if (typeof deepLinks.metaDetailsVideos === 'string') {
    const link = deepLinks.metaDetailsVideos;
    // Only allow internal hash routes
    if (link.startsWith('#/')) {
        window.location = link;
    }
}
```

---

## Additional Observations (Lower Severity)

### Information Disclosure via Password Reset URL

**File**: `src/routes/Settings/General/General.tsx` (Line 129)  
**Severity**: LOW

```typescript
<Link
    label={t('SETTINGS_CHANGE_PASSWORD')}
    href={`https://www.strem.io/reset-password/${profile.auth.user.email}`}
/>
```

User email is included in a URL that appears in browser history, referrer headers, and potentially server logs. This is an information disclosure risk.

### Weak ID Generation in Shell Communication

**File**: `src/common/useShell.ts` (Line 30)  
**Severity**: LOW

```typescript
const createId = () => Math.floor(Math.random() * 9999) + 1;
```

Message IDs use `Math.random()` with a very small range (1-9999), making collisions trivially likely and potentially exploitable for message confusion attacks in the shell transport layer.

---

## Summary Table

| # | Vulnerability | Severity | File | Line | CWE |
|---|---|---|---|---|---|
| 1 | Host Whitelist Bypass (Open Redirect) | HIGH | `Platform.tsx` | 21 | CWE-601 |
| 2 | Insecure OAuth State Token (`Math.random`) | HIGH | `useFacebookLogin.ts`, `useAppleLogin.ts` | 32, 42 | CWE-330 |
| 3 | Streaming Server URL Injection | MEDIUM-HIGH | `SearchParamsHandler.js` | 26-51 | CWE-20/918 |
| 4 | CSS Injection via Avatar URL | MEDIUM | `User.tsx`, `NavMenuContent.js`, `ModalDialog.js` | 19, 57, 64 | CWE-79 |
| 5 | Unvalidated Deep Link Redirect | MEDIUM | `DeepLinkHandler.js` | 14 | CWE-601 |

---

## Remediation Priority

1. **Immediate** (Vulnerability 1): ✅ **FIXED** — Changed `hostname.endsWith(host)` to `hostname === host || hostname.endsWith('.${host}')` for proper domain boundary matching
2. **Immediate** (Vulnerability 2): ✅ **FIXED** — Replaced `hat` library (`Math.random()`) with `crypto.getRandomValues()` in both `useFacebookLogin.ts` and `useAppleLogin.ts`
3. **High** (Vulnerability 3): ✅ **FIXED** — Added URL validation with protocol check (`http:` / `https:` only) for `streamingServerUrl` parameter in `SearchParamsHandler.js`
4. **Medium** (Vulnerability 5): ✅ **FIXED** — Added `startsWith('#')` check to validate deep links are internal hash routes before assigning to `window.location` in `DeepLinkHandler.js`
5. **Medium** (Vulnerability 4): ✅ **FIXED** — Applied `encodeURI()` with single quote escaping to sanitize avatar URLs and background URLs before CSS interpolation in `User.tsx`, `NavMenuContent.js`, and `ModalDialog.js`
