# IDE plugins and MCP server

Docker Scanner can be used from your editor and from AI assistants via an **MCP server** and **IDE plugins** for VS Code/Cursor and JetBrains.

---

## In plain language (start here)

**What are these?**

- **VS Code / Cursor extension** — A small add-on for VS Code or Cursor. Once installed, you can run a scan from a menu or the command palette without typing commands. Good if you use VS Code or Cursor and want to scan images from the editor.
- **JetBrains plugin** — The same idea for IntelliJ IDEA, GoLand, and other JetBrains IDEs. You install the plugin, then use **Tools → Scan image with Docker Scanner**.
- **MCP server** — A helper that runs in the background and lets **AI assistants** (like Cursor’s AI or Claude) run scans for you when you ask in chat. The AI can call “scan this image” and show you the results. It does **not** appear in the plugin list; you add it once in Cursor/IDE settings.

**What you need first**

- The **scanner** itself: either build it from this repo (`go build -o scanner ./cmd/cli`) and put it in your PATH, or use the Docker method (see [Getting started](getting-started.md)).
- **Trivy** in PATH (the scanner uses it under the hood). The [install script](getting-started.md) can set this up for you.

The IDE plugins and MCP server currently run **image** scans. The CLI also supports **rootfs/LXC** with `--fs <path>` and `--lxc <name>`; see [CLI reference](cli-reference.md#scan) and [Help — Runtimes](HELP.md#runtimes-podman-lxc).

---

### How to use the VS Code / Cursor extension (step-by-step)

1. **Install the scanner and Trivy** (if you haven’t). Run the install-deps script for your OS (see [Getting started](getting-started.md)), then build: `go build -o scanner ./cmd/cli`. Put the folder that contains `scanner` (and Trivy) in your PATH.
2. **Get the extension**
   - **From the Marketplace (if published):** In VS Code or Cursor, open the Extensions view (Ctrl+Shift+X / Cmd+Shift+X), search for **Docker Scanner**, click Install.
   - **From this repo (development):** Open the `ide/vscode` folder in VS Code/Cursor. In a terminal run `npm install`, then `npm run compile`. Press **F5** to open a new window with the extension loaded.
3. **Run a scan.** Open the Command Palette (Ctrl+Shift+P / Cmd+Shift+P), type **Docker Scanner**, and choose **Docker Scanner: Scan image**. Enter the image name when asked (e.g. `alpine:latest`). Optionally enter a Dockerfile path or leave it blank. Output appears in the **Docker Scanner** output channel at the bottom.
4. **If you have a Dockerfile open:** Right‑click in the editor or run **Docker Scanner: Scan image for current Dockerfile**, then enter the image name. The current file is used as the Dockerfile.

---

### How to use the JetBrains plugin (step-by-step)

1. **Install the scanner and Trivy** (see above) and ensure they are in your system PATH.
2. **Get the plugin**
   - **From the Marketplace (if published):** In IntelliJ/GoLand, go to **Settings → Plugins**, search for **Docker Scanner**, click Install, then restart the IDE.
   - **From this repo:** Open the `ide/jetbrains` folder in IntelliJ. Run **Gradle → buildPlugin**. Then **Settings → Plugins → gear icon → Install Plugin from Disk** and select the ZIP from `ide/jetbrains/build/distributions/`.
3. **Run a scan.** In the menu choose **Tools → Scan image with Docker Scanner**. Enter the image name (e.g. `alpine:latest`) and, if you want, a Dockerfile path. The Run tool window at the bottom shows the scan output.

---

### How to use the MCP server in Cursor (step-by-step)

The MCP server lets the **AI in Cursor** run scans when you ask. It does **not** show up in the Extensions list; you add it once in Cursor’s MCP settings.

1. **Install the scanner and Trivy** (see above). You need Go so Cursor can run the server (e.g. `go run ./cmd/mcp-server`).
2. **Open Cursor’s MCP settings.** In Cursor: **Settings → Cursor Settings → MCP** (or open the MCP config file your setup uses).
3. **Add the Docker Scanner server.** Add a block like this (replace the path with your actual docker-scanner folder):

   **Windows (run from repo):**
   ```json
   "docker-scanner": {
     "command": "go",
     "args": ["run", "./cmd/mcp-server"],
     "cwd": "C:\\Users\\YourName\\Git Projects\\docker-scanner"
   }
   ```

   **macOS / Linux (run from repo):**
   ```json
   "docker-scanner": {
     "command": "go",
     "args": ["run", "./cmd/mcp-server"],
     "cwd": "/home/you/projects/docker-scanner"
   }
   ```

   Make sure the whole `mcpServers` section is valid JSON (commas between entries, no trailing comma on the last one).
4. **Save and restart Cursor** if needed. The AI can then use the scanner. Try: “Scan the image alpine:latest” or “Run a vulnerability scan on nginx:alpine.” The AI will call the tool and show you the summary and findings.

**Note:** The MCP server is not a “plugin” you search for in VS Code or JetBrains. It’s a small program that Cursor starts and talks to; you only configure it in MCP settings.

---

## Making the extension and plugin show up in search

**MCP server:** The MCP server does **not** appear in any plugin or extension search. Users add it by editing Cursor (or other MCP client) settings and pointing to the repo or a built binary. There is no marketplace listing for it.

**VS Code extension:** To have the extension appear when people search in VS Code or Cursor’s Extensions view, you must **publish it to the VS Code Marketplace**.

**JetBrains plugin:** To have the plugin appear when people search in **Settings → Plugins**, you must **publish it to the JetBrains Marketplace**.

---

### Publishing the VS Code extension to the Marketplace

1. **Create a publisher account**
   - Go to [Visual Studio Marketplace](https://marketplace.visualstudio.com/) and sign in with a Microsoft or GitHub account.
   - Click your profile (top right) → **Create Publisher**. Choose a **Publisher ID** (e.g. your username or org name). This ID will appear in the extension URL and cannot be changed later.

2. **Install the packaging tool**
   - In a terminal: `npm install -g @vscode/vsce`

3. **Set the publisher in the extension**
   - In `ide/vscode/package.json`, set `"publisher"` to your Publisher ID (e.g. `"yourname"` or `"your-org"`). The Marketplace uses `publisher.extensionName` as the unique ID.

4. **Create a Personal Access Token (PAT)**
   - Go to [Azure DevOps](https://dev.azure.com/) → create or open an organization → **User settings** (top right) → **Personal access tokens**.
   - Create a new token with **Marketplace (Publish)** scope (or **Full access** for simplicity). Copy the token.

5. **Log in and publish**
   - From the `ide/vscode` folder run:
     - `vsce login <your-publisher-id>` (paste the PAT when prompted), or
     - `vsce publish -p <PAT>` to publish without storing the token.
   - Run `vsce publish` to package and publish. After a short delay, the extension will appear when users search for “Docker Scanner” in Extensions.

6. **Updating later**
   - Bump `version` in `package.json`, then run `vsce publish` again.

Official details: [Publishing Extensions (VS Code)](https://code.visualstudio.com/api/working-with-extensions/publishing-extension).

---

### Publishing the JetBrains plugin to the Marketplace

1. **Create a vendor profile**
   - Go to [JetBrains Marketplace](https://plugins.jetbrains.com/) and sign in.
   - Accept the Marketplace Developer Agreement and create a **Vendor** (individual or organization). This is the name that appears as the plugin author.

2. **Build the plugin**
   - Open `ide/jetbrains` in IntelliJ and run **Gradle → buildPlugin**. The ZIP is in `build/distributions/`.

3. **Upload the plugin**
   - In the Marketplace site: **Your account → Upload plugin**.
   - Upload the ZIP, fill in the plugin page (description, license, link to source code, tags like “Docker”, “security”, “vulnerability”).
   - Submit for review. Once approved, the plugin will appear when users search in **Settings → Plugins**.

4. **Updating later**
   - Bump `version` in `ide/jetbrains/build.gradle.kts`, rebuild, then upload a new version from the plugin’s page on the Marketplace.

Details: [Uploading a new plugin (JetBrains)](https://plugins.jetbrains.com/docs/marketplace/uploading-a-new-plugin.html).

---

## MCP server

The **Model Context Protocol (MCP)** server exposes the scanner as tools that AI assistants (e.g. Cursor, Claude Desktop) can call: scan an image, optionally with a Dockerfile, and get a JSON summary of findings.

### Running the MCP server

From the repo root (with Go and Trivy in PATH):

```bash
go run ./cmd/mcp-server
```

The server uses **stdio** transport: the IDE or MCP client spawns this process and talks over stdin/stdout. It does not listen on a port.

### Tools

| Tool | Description |
|------|-------------|
| **scan_image** | Scan a container image (and optionally a Dockerfile). Arguments: `image` (required), `dockerfile`, `severity`, `offline`, `cache_dir`. Returns JSON with `findings_count`, `summary`, `findings` (CVE, severity, exploitable, remediation), and `report_dir`. |
| **db_update** | Placeholder for Trivy DB update (not implemented; use Trivy directly or run a scan without `offline`). |

### Adding the MCP server in Cursor

1. Build or run the server: `go run ./cmd/mcp-server` (or install a built binary and use that path).
2. In Cursor: **Settings → Cursor Settings → MCP** (or edit your MCP config file).
3. Add a server entry, for example:

**Option A – run from repo (development):**

```json
{
  "mcpServers": {
    "docker-scanner": {
      "command": "go",
      "args": ["run", "./cmd/mcp-server"],
      "cwd": "C:\\path\\to\\docker-scanner"
    }
  }
}
```

**Option B – use built binary:**

```json
{
  "mcpServers": {
    "docker-scanner": {
      "command": "C:\\path\\to\\docker-scanner\\scanner-mcp",
      "args": []
    }
  }
}
```

On macOS/Linux use `"command": "go"` with `"args": ["run", "./cmd/mcp-server"]` and the appropriate `cwd`, or the path to your built MCP binary. After saving, the AI can use the `scan_image` and `db_update` tools.

---

## VS Code / Cursor extension

Location: **`ide/vscode/`**.

### Install (development)

1. Open `ide/vscode` in VS Code or Cursor.
2. Run **npm install**, then **npm run compile**.
3. Press **F5** to launch a Development Host with the extension loaded.

### Commands

- **Docker Scanner: Scan image** — Prompts for image reference and optional Dockerfile path; runs the scanner and shows output in the **Docker Scanner** output channel.
- **Docker Scanner: Scan image for current Dockerfile** — In a Dockerfile, run from Command Palette or right‑click; prompts for image and uses the current file as the Dockerfile.

### Settings

- **dockerScanner.cliPath** — Command to run (default: `scanner`). Use `go run ./cmd/cli` to run from repo.
- **dockerScanner.reportsDir** — Output directory for reports (default: `./reports`).

### Requirements

- **Scanner CLI** in PATH (or set `dockerScanner.cliPath`).
- **Trivy** in PATH.

See **ide/vscode/README.md** for more detail.

---

## JetBrains plugin (IntelliJ, GoLand, etc.)

Location: **`ide/jetbrains/`**.

### Build and install

1. Open `ide/jetbrains` in IntelliJ IDEA (install **Plugin DevKit** from the marketplace if needed).
2. **Gradle → buildPlugin**.
3. **Settings → Plugins → gear → Install Plugin from Disk** → choose `ide/jetbrains/build/distributions/docker-scanner-jetbrains-0.1.0.zip`.

### Usage

- **Tools → Scan image with Docker Scanner** — Prompts for image and optional Dockerfile path; runs the scanner and shows output in the **Run** tool window.

### Requirements

- **Scanner CLI** and **Trivy** in PATH.

See **ide/jetbrains/README.md** for more detail.

---

## Summary

| Use case | What to use |
|----------|-------------|
| Use scanner from Cursor/Claude (AI) | Add **MCP server** in Cursor/MCP config; AI can call `scan_image` and `db_update`. |
| Use scanner from VS Code/Cursor (UI) | Install **VS Code extension** from `ide/vscode`; use commands from Command Palette or Dockerfile context menu. |
| Use scanner from IntelliJ/GoLand | Install **JetBrains plugin** from `ide/jetbrains`; use **Tools → Scan image with Docker Scanner**. |
| CLI / CI | Use **scanner** CLI or **baseline** as documented in [CLI reference](cli-reference.md) and [Baseline](baseline.md). |

All of the above require the **scanner** (and for full scans, **Trivy**) to be available; see [Getting started](getting-started.md) and [Help](HELP.md).
