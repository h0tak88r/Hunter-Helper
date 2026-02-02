# Hunter Helper

**Hunter Helper** is a Burp Suite extension designed to streamline the workflow of bug hunters and pentesters. It provides a comprehensive suite of tools for rapid request conversion, POC generation, security analysis, and beautiful, shareable request/response visualization.

## 🚀 Features

### 1. Smart Sharing & Documentation

#### Copy as Image
Generate beautiful, syntax-highlighted images of your HTTP requests and responses directly to your clipboard. Perfect for reports, write-ups, or sharing with the team.
- **Side-by-Side View**: Mimics the Burp Suite interface with a split layout (Request Left / Response Right)
- **Auto-Censoring**: Automatically masks sensitive headers like `Cookie`, `Authorization`, and `Set-Cookie` with `********`
- **Noise Filtering**: Hides standard noise headers (e.g., `Connection`, `Cache-Control`, `CSP`, `CF-*`, `Sec-Fetch-*`) to focus on important data
- **Smart Formatting**:
  - Request bodies (JSON/XML) are pretty-printed and indented
  - Response bodies are kept raw (to preserve server output) but wrapped to fit the image
  - Long tokens and strings are automatically wrapped to prevent layout breaking

#### Copy as Markdown
Export request/response as clean markdown code blocks, ready for documentation or GitHub.
- **Smart Header Filtering**: Auto-censors sensitive data, removes noise headers
- **Clean Code Blocks**: Proper HTTP syntax highlighting
- **Full Content**: Includes request/response bodies
- **Output to Burp Console**: Content printed to Output tab for easy copying

#### Copy Session Headers
One-click extraction of all session-related headers (Authorization, Cookies, CSRF tokens) to clipboard.

### 2. CSRF Testing

#### Copy as CSRF HTML POC
Generate ready-to-use HTML proof-of-concept for CSRF testing.
- **Auto-submit Form**: JavaScript automatically submits the form on page load
- **Smart Parameter Extraction**: Includes POST body parameters, excludes cookies (browsers send them automatically)
- **Multiple Encoding Support**: Handles `application/x-www-form-urlencoded` and `multipart/form-data`
- **HTML Entity Escaping**: Proper escaping for parameter names and values
- **Output to Console**: Full HTML printed to Burp Output tab

#### Test CSRF POC in Browser
Save CSRF POC to a temporary file and copy `file:///` URL to clipboard.
- **One-Click Testing**: Instant browser testing without manual file creation
- **Any Browser**: Works with Chrome, Firefox, Safari, or any browser
- **Shareable**: File can be shared with team members
- **Auto-cleanup**: Temp file deleted when Burp exits

### 3. Security Analysis

#### Decode JWT
Automatically finds and decodes JWT tokens from requests/responses with comprehensive security recommendations.
- **Auto-Detection**: Finds JWTs in headers, bodies, and URLs
- **Complete Decoding**: Shows header, payload, and signature
- **Security Recommendations**:
  - **`none` algorithm**: Critical warning with bypass instructions
  - **HS256/HS384/HS512**: Brute force attack guidance
  - **RS256/RS384/RS512**: Algorithm confusion attack notes
  - **ES256/ES384/ES512**: ECDSA-specific vulnerabilities
- **Claims Analysis**: Checks expiration, issuer, subject, and custom claims

### 4. Content-Type Conversion
Easily convert your requests between common formats with a single click.
- **XML ↔ JSON ↔ URL-Encoded**
- **JSON POST → GET Request** (simulates parameter pollution/method switching)

### 5. POC Generation
- **Copy as fetch() POC**: Generates a clean, ready-to-run JavaScript `fetch` code snippet for the selected request. Handles headers, body, and credentials automatically.

## 📦 Installation

1. **Prerequisites**: Ensure you have **Jython** configured in Burp Suite.
   - Download [Jython Standalone JAR](https://www.jython.org/download)
   - Go to **Extender > Options > Python Environment**
   - Select your downloaded Jython JAR

2. **Install Extension**:
   - Go to **Extender > Extensions**
   - Click **Add**
   - **Extension Type**: Python
   - **Extension File**: Select `hunter_helper.py`

3. **Verify**: You should see "Hunter Helper - Loaded Successfully" in the Output tab.

## 🛠️ Usage

1. **Right-click** on any HTTP request in the **Proxy History**, **Repeater**, or **Intruder**
2. Navigate to the **Hunter Helper** context menu
3. Choose your desired action:
   - **Copy as image** - Beautiful side-by-side request/response images
   - **Copy as Markdown** - Clean markdown for documentation
   - **Copy Session Headers** - Extract auth headers
   - **Decode JWT** - Find and analyze JWT tokens with security tips
   - **Copy as CSRF HTML POC** - Generate CSRF proof-of-concept
   - **Test CSRF POC in Browser** - Instant browser testing with file:/// URL
   - **Convert to JSON/XML/URL-encoded** - Format conversion
   - **Copy as fetch POC** - JavaScript fetch snippet

## 📋 Example Output

### CSRF POC Example
```html
<!DOCTYPE html>
<html>
  <!-- CSRF PoC - Hunter Helper -->
  <body>
    <form method="POST" action="https://example.com/api/update">
      <input type="text" name="email" value="attacker@evil.com">
      <input type="text" name="role" value="admin">
      <input type="submit" value="Submit Request">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### JWT Analysis Example
```
[+] JWT Token Found in Authorization header
[+] Algorithm: HS256

[+] Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

[+] Payload:
{
  "sub": "user123",
  "role": "admin",
  "exp": 1735689600
}

[!] SECURITY RECOMMENDATIONS:
- HS256 uses a symmetric key - try brute forcing with hashcat or jwt_tool
- Check if the server accepts 'none' algorithm (algorithm confusion)
- Token expires: 2025-01-01 00:00:00 (EXPIRED)
```

## 🎯 Use Cases

- **Bug Bounty Hunting**: Quick CSRF POC generation, JWT analysis, clean screenshots for reports
- **Penetration Testing**: Rapid request manipulation, format conversion, POC creation
- **Security Research**: JWT vulnerability testing, session analysis
- **Documentation**: Beautiful request/response images and markdown exports
- **Team Collaboration**: Share POCs, findings, and request details easily

## 🙏 Credits
Built for bug hunters, by bug hunters. Contributions and feedback welcome!
