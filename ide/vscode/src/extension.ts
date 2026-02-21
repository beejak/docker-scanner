import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execAsync = promisify(exec);

const OUTPUT_CHANNEL_NAME = 'Docker Scanner';

export function activate(context: vscode.ExtensionContext) {
	const output = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);

	context.subscriptions.push(
		vscode.commands.registerCommand('docker-scanner.scanImage', async () => {
			const image = await vscode.window.showInputBox({
				prompt: 'Image to scan (e.g. alpine:latest or myregistry.io/app:v1)',
				placeHolder: 'alpine:latest',
				validateInput: (v) => (!v || !v.trim() ? 'Image is required' : null),
			});
			if (!image?.trim()) { return; }
			const dockerfile = await vscode.window.showInputBox({
				prompt: 'Optional Dockerfile path (relative to workspace or absolute)',
				placeHolder: 'leave empty to skip',
			});
			await runScan(output, image.trim(), dockerfile?.trim() || undefined);
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('docker-scanner.scanImageFromDockerfile', async () => {
			const doc = vscode.window.activeTextEditor?.document;
			const dockerfilePath = doc?.fileName;
			if (!dockerfilePath || !doc || doc.languageId !== 'dockerfile') {
				vscode.window.showWarningMessage('Open a Dockerfile first.');
				return;
			}
			const image = await vscode.window.showInputBox({
				prompt: 'Image to scan (e.g. alpine:latest). Dockerfile will be scanned for misconfigurations.',
				placeHolder: 'alpine:latest',
				validateInput: (v) => (!v || !v.trim() ? 'Image is required' : null),
			});
			if (!image?.trim()) { return; }
			const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
			const dfRelative = workspaceRoot ? path.relative(workspaceRoot, dockerfilePath) : dockerfilePath;
			await runScan(output, image.trim(), dfRelative || dockerfilePath);
		})
	);
}

async function runScan(
	output: vscode.OutputChannel,
	image: string,
	dockerfile?: string
): Promise<void> {
	output.clear();
	output.show();
	output.appendLine(`Scanning image: ${image}${dockerfile ? ` (Dockerfile: ${dockerfile})` : ''}`);

	const config = vscode.workspace.getConfiguration('dockerScanner');
	const cliPath = config.get<string>('cliPath') ?? 'scanner';
	const reportsDir = config.get<string>('reportsDir') ?? './reports';

	const args = [
		'scan',
		'--image', image,
		'--output-dir', reportsDir,
		'--format', 'markdown,html',
	];
	if (dockerfile) {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		const fullPath = root ? path.resolve(root, dockerfile) : path.resolve(dockerfile);
		args.push('--dockerfile', fullPath);
	}

	const cmd = cliPath.includes(' ') ? `${cliPath} ${args.join(' ')}` : [cliPath, ...args];
	const cmdStr = Array.isArray(cmd) ? cmd.join(' ') : cmd;
	output.appendLine(`Running: ${cmdStr}`);

	try {
		const { stdout, stderr } = await execAsync(cmdStr, {
			cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
			maxBuffer: 10 * 1024 * 1024,
		});
		if (stdout) { output.append(stdout); }
		if (stderr) { output.append(stderr); }
		output.appendLine('\nDone. Reports in ' + reportsDir);
		vscode.window.showInformationMessage(`Docker Scanner: scan complete. Reports in ${reportsDir}`);
	} catch (e: unknown) {
		const err = e as { message?: string; stderr?: string; stdout?: string };
		output.appendLine('Error: ' + (err.message || String(e)));
		if (err.stderr) { output.append(err.stderr); }
		if (err.stdout) { output.append(err.stdout); }
		vscode.window.showErrorMessage('Docker Scanner: scan failed. See output channel.');
	}
}

export function deactivate() {}
