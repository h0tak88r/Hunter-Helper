# Hunter Helper

**Hunter Helper** is a Burp Suite extension designed to streamline the workflow of bug hunters and pentesters. It provides a suite of tools for rapid request conversion, POC generation, and beautiful, shareable request/response visualization.

## Features

### 1. Smart Sharing (Copy as Image)
Generate beautiful, syntax-highlighted images of your HTTP requests and responses directly to your clipboard. Perfect for reports, write-ups, or sharing with the team.
-   **Side-by-Side View**: Mimics the Burp Suite interface with a split layout (Request Left / Response Right).
-   **Auto-Censoring**: Automatically masks sensitive headers like `Cookie`, `Authorization`, and `Set-Cookie` with `********`.
-   **Noise Filtering**: Hides standard biological headers (e.g., `Connection`, `Cache-Control`, `Sec-Fetch-*`) to focus on the important data.
-   **Smart Formatting**:
    -   Request bodies (JSON/XML) are pretty-printed and indented.
    -   Response bodies are kept raw (to preserve server output) but wrapped to fit the image.
    -   Long tokens and strings are automatically wrapped to prevent layout breaking.

### 2. Content-Type Conversion
Easily convert your requests between common formats with a single click.
-   **XML ↔ JSON ↔ URL-Encoded**
-   **JSON POST → GET Request** (simulates parameter pollution/method switching)

### 3. POC Generation
-   **Copy as fetch() POC**: Generates a clean, ready-to-run JavaScript `fetch` code snippet for the selected request. Handles headers, body, and credentials automatically.

## Installation

1.  **Prerequisites**: Ensure you have **Jython** configured in Burp Suite.
    -   Download [Jython Standalone JAR](https://www.jython.org/download).
    -   Go to **Extender > Options > Python Environment**.
    -   Select your downloaded Jython JAR.
2.  **Install Extension**:
    -   Go to **Extender > Extensions**.
    -   Click **Add**.
    -   **Extension Type**: Python.
    -   **Extension File**: Select `hunter_helper.py`.
3.  **Verify**: You should see "Hunter Helper - Loaded Successfully" in the Output tab.

## Usage

1.  **Right-click** on any HTTP request in the **Proxy History** or **Repeater**.
2.  Navigate to the **Hunter Helper** context menu.
3.  Choose your desired action:
    -   *Copy as image*
    -   *Convert to JSON/XML/etc.*
    -   *Copy as fetch POC*
