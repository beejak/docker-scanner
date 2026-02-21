# Docker Scanner – JetBrains Plugin

Run container image scans from IntelliJ IDEA, GoLand, or other JetBrains IDEs.

## Build and install

1. Open the `ide/jetbrains` folder in IntelliJ IDEA (with Plugin DevKit installed).
2. Run **Gradle → Tasks → intellij → buildPlugin**.
3. Install from disk: **Settings → Plugins → gear → Install Plugin from Disk** and select `ide/jetbrains/build/distributions/docker-scanner-jetbrains-0.1.0.zip`.

Or run **Run IDE with Plugin** from the run configuration to test in a sandbox IDE.

## Usage

- **Tools → Scan image with Docker Scanner** — Prompts for image reference and optional Dockerfile path, then runs the scanner CLI. Output appears in the Run tool window.

## Requirements

- **Scanner CLI** in PATH (build from repo: `go build -o scanner ./cmd/cli`).
- **Trivy** in PATH (see [getting-started](../../docs/getting-started.md)).

## MCP

To use the scanner from an AI assistant (e.g. Cursor), run the MCP server and add it in Cursor settings. See [IDE and MCP](../../docs/ide-and-mcp.md).

## Publishing to the JetBrains Marketplace

So the plugin appears when users search in **Settings → Plugins**: create a vendor on [JetBrains Marketplace](https://plugins.jetbrains.com/), build the plugin (Gradle → buildPlugin), then upload the ZIP from **Your account → Upload plugin**. Full steps: [IDE and MCP — Publishing the JetBrains plugin](../../docs/ide-and-mcp.md#publishing-the-jetbrains-plugin-to-the-marketplace).
