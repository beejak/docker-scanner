import * as vscode from 'vscode';
import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execAsync = promisify(exec);
const OUTPUT_CHANNEL_NAME = 'Docker Scanner';

let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
	const output = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);

	// Status bar: shows scan progress, idle when not scanning.
	statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
	statusBarItem.text = '$(shield) Scanner';
	statusBarItem.tooltip = 'Docker Scanner — click to scan image';
	statusBarItem.command = 'docker-scanner.scanImage';
	statusBarItem.show();
	context.subscriptions.push(statusBarItem);

	// ── Scan image (prompt for image ref) ──────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('docker-scanner.scanImage', async () => {
			const image = await vscode.window.showInputBox({
				prompt: 'Image to scan (e.g. alpine:latest or myregistry.io/app:v1)',
				placeHolder: 'alpine:latest',
				validateInput: (v) => (!v?.trim() ? 'Image reference is required' : null),
			});
			if (!image?.trim()) { return; }
			await runScan(output, { image: image.trim() });
		})
	);

	// ── Scan image from active Dockerfile ──────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('docker-scanner.scanImageFromDockerfile', async () => {
			const doc = vscode.window.activeTextEditor?.document;
			if (!doc || doc.languageId !== 'dockerfile') {
				vscode.window.showWarningMessage('Open a Dockerfile first.');
				return;
			}
			const image = await vscode.window.showInputBox({
				prompt: 'Image to scan. Dockerfile will also be scanned for misconfigurations.',
				placeHolder: 'alpine:latest',
				validateInput: (v) => (!v?.trim() ? 'Image reference is required' : null),
			});
			if (!image?.trim()) { return; }
			const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
			const dfPath = root ? path.relative(root, doc.fileName) : doc.fileName;
			await runScan(output, { image: image.trim(), dockerfile: dfPath });
		})
	);

	// ── Open Web UI in browser ─────────────────────────────────────────────
	// Starts scanner-server if not already running, then opens the browser.
	context.subscriptions.push(
		vscode.commands.registerCommand('docker-scanner.openWebUI', async () => {
			const config = vscode.workspace.getConfiguration('dockerScanner');
			const port = config.get<number>('webUIPort') ?? 8080;
			const url = `http://localhost:${port}`;

			// Check if server is already up.
			const alreadyUp = await isServerUp(url);
			if (!alreadyUp) {
				const serverPath = config.get<string>('serverPath') ?? 'scanner-server';
				output.show();
				output.appendLine(`Starting scanner server on port ${port}…`);
				const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
				const proc = spawn(serverPath, ['-port', String(port)], {
					cwd,
					detached: false,
					stdio: ['ignore', 'pipe', 'pipe'],
				});
				proc.stdout?.on('data', (d: Buffer) => output.append(d.toString()));
				proc.stderr?.on('data', (d: Buffer) => output.append(d.toString()));
				// Give it a moment to start, then open browser.
				await new Promise(r => setTimeout(r, 1500));
			}
			vscode.env.openExternal(vscode.Uri.parse(url));
			vscode.window.showInformationMessage(`Docker Scanner Web UI: ${url}`);
		})
	);

	// ── Check host runc ────────────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('docker-scanner.checkRuntime', async () => {
			const config = vscode.workspace.getConfiguration('dockerScanner');
			const cliPath = config.get<string>('cliPath') ?? 'scanner';
			const reportsDir = config.get<string>('reportsDir') ?? './reports';
			output.clear();
			output.show();
			output.appendLine('Checking host runc for container escape CVEs…');
			statusBarItem.text = '$(sync~spin) Checking runc…';
			try {
				const cmd = `${cliPath} scan --image scratch --check-runtime --output-dir ${reportsDir} --format markdown 2>&1 || true`;
				const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
				const { stdout, stderr } = await execAsync(cmd, { cwd: root, maxBuffer: 4 * 1024 * 1024 });
				if (stdout) { output.append(stdout); }
				if (stderr) { output.append(stderr); }
			} catch (e: unknown) {
				const err = e as { message?: string };
				output.appendLine('Error: ' + (err.message ?? String(e)));
			} finally {
				statusBarItem.text = '$(shield) Scanner';
			}
		})
	);
}

// ── Core scan runner ──────────────────────────────────────────────────────────

interface ScanOptions {
	image?: string;
	rootfs?: string;
	dockerfile?: string;
}

async function runScan(output: vscode.OutputChannel, opts: ScanOptions): Promise<void> {
	const config = vscode.workspace.getConfiguration('dockerScanner');
	const cliPath       = config.get<string>('cliPath')         ?? 'scanner';
	const reportsDir    = config.get<string>('reportsDir')      ?? './reports';
	const formats       = config.get<string>('formats')         ?? 'sarif,markdown,html,csv';
	const severity      = config.get<string>('severity')        ?? '';
	const failOnSev     = config.get<string>('failOnSeverity')  ?? '';
	const checkRuntime  = config.get<boolean>('checkRuntime')   ?? false;
	const sbom          = config.get<boolean>('sbom')           ?? false;
	const offline       = config.get<boolean>('offline')        ?? false;

	output.clear();
	output.show();

	const target = opts.image ? `image: ${opts.image}` : `rootfs: ${opts.rootfs}`;
	output.appendLine(`Docker Scanner — scanning ${target}`);

	const args = ['scan'];
	if (opts.image)      { args.push('--image',      opts.image); }
	if (opts.rootfs)     { args.push('--fs',          opts.rootfs); }
	if (opts.dockerfile) {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		const fullPath = root ? path.resolve(root, opts.dockerfile) : path.resolve(opts.dockerfile);
		args.push('--dockerfile', fullPath);
	}
	args.push('--output-dir', reportsDir);
	args.push('--format', formats);
	if (severity)    { args.push('--severity', severity); }
	if (failOnSev)   { args.push('--fail-on-severity', failOnSev); }
	if (checkRuntime){ args.push('--check-runtime'); }
	if (sbom)        { args.push('--sbom'); }
	if (offline)     { args.push('--offline'); }

	const cmdStr = [cliPath, ...args].join(' ');
	output.appendLine(`Running: ${cmdStr}\n`);

	statusBarItem.text = '$(sync~spin) Scanning…';
	statusBarItem.tooltip = `Scanning ${opts.image ?? opts.rootfs}`;

	try {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		const { stdout, stderr } = await execAsync(cmdStr, {
			cwd: root,
			maxBuffer: 20 * 1024 * 1024,
		});
		if (stdout) { output.append(stdout); }
		if (stderr) { output.append(stderr); }
		output.appendLine(`\n✓ Scan complete. Reports in ${reportsDir}`);
		statusBarItem.text = '$(pass) Scanner — done';
		vscode.window.showInformationMessage(
			`Docker Scanner: scan complete. Reports in ${reportsDir}`,
			'Open Report'
		).then(sel => {
			if (sel === 'Open Report') {
				const mdPath = path.join(
					root ?? '',
					reportsDir.replace('./', ''),
					'report.md'
				);
				vscode.commands.executeCommand('markdown.showPreview', vscode.Uri.file(mdPath));
			}
		});
	} catch (e: unknown) {
		const err = e as { message?: string; stderr?: string; stdout?: string; code?: number };
		// Exit code 1 from --fail-on-severity is not a crash — show output normally.
		if (err.stdout) { output.append(err.stdout); }
		if (err.stderr) { output.append(err.stderr); }
		if (err.code === 1) {
			output.appendLine('\n⚠ Policy gate triggered (--fail-on-severity). See findings above.');
			statusBarItem.text = '$(warning) Scanner — policy fail';
			vscode.window.showWarningMessage('Docker Scanner: policy violation — Critical/High findings found. Check Output panel.');
		} else {
			output.appendLine('\n✗ Error: ' + (err.message ?? String(e)));
			statusBarItem.text = '$(error) Scanner — error';
			vscode.window.showErrorMessage('Docker Scanner: scan failed. See Output panel.');
		}
	} finally {
		setTimeout(() => {
			statusBarItem.text = '$(shield) Scanner';
			statusBarItem.tooltip = 'Docker Scanner — click to scan image';
		}, 5000);
	}
}

// ── Utility ───────────────────────────────────────────────────────────────────

async function isServerUp(url: string): Promise<boolean> {
	try {
		await execAsync(`curl -sf ${url}/health`);
		return true;
	} catch {
		return false;
	}
}

export function deactivate() {}
