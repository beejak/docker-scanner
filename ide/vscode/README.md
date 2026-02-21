# Docker Scanner – VS Code Extension

Run container image scans from VS Code.

## Commands

- **Docker Scanner: Scan image** — Prompt for image reference (and optional Dockerfile path), then run the scanner. Output appears in the "Docker Scanner" output channel.
- **Docker Scanner: Scan image for current Dockerfile** — Right-click in a Dockerfile or run from Command Palette. Prompts for image; uses the current file as the Dockerfile for misconfiguration scan.

## Requirements

- **Scanner CLI** in PATH (build from repo: `go build -o scanner ./cmd/cli`, or run with `go run ./cmd/cli`).
- **Trivy** in PATH (see [getting-started](../docs/getting-started.md)).

## Settings

- `dockerScanner.cliPath` — Command to run (default: `scanner`). Use `go run ./cmd/cli` to run from repo root.
- `dockerScanner.reportsDir` — Output directory for reports (default: `./reports`).

## MCP

To use the scanner from an AI assistant (e.g. Cursor), run the MCP server and add it in Cursor settings. See [IDE and MCP](../../docs/ide-and-mcp.md).

## Publishing to the VS Code Marketplace

So the extension appears when users search “Docker Scanner” in Extensions: create a publisher on the [VS Code Marketplace](https://marketplace.visualstudio.com/), set `publisher` in `package.json` to your publisher ID, then run `npm i -g @vscode/vsce` and `vsce publish` (with a Personal Access Token from Azure DevOps). Full step-by-step: [IDE and MCP — Making the extension show up in search](../../docs/ide-and-mcp.md#publishing-the-vs-code-extension-to-the-marketplace).
