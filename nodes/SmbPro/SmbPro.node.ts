import {
	NodeOperationError,
	type IDataObject,
	type IExecuteFunctions,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
} from 'n8n-workflow';
import { ensureMd4Support } from './md4';

ensureMd4Support();

// eslint-disable-next-line @typescript-eslint/no-var-requires
const SMB2 = require('v9u-smb2');

/* ------------------------------------------------------------------ */
/* Promise wrappers around the callback API of v9u-smb2                */
/* ------------------------------------------------------------------ */

interface SmbStats {
	name?: string;
	size: number;
	mtime?: number | Date;
	birthtime?: number | Date;
	ctime?: number | Date;
	isDirectory: () => boolean;
}

/**
 * Lists a folder including metadata.
 *
 * A single QUERY_DIRECTORY already returns size, timestamps and attributes for
 * every entry, so no per-file CREATE/CLOSE is needed. This avoids opening every
 * file on the share (which triggers antivirus scans and breaks oplocks of users
 * who have the file open).
 */
function pReaddirStats(c: any, p: string): Promise<SmbStats[]> {
	return new Promise((res, rej) =>
		c.readdir(p, { stats: true }, (e: Error, f: SmbStats[]) => (e ? rej(e) : res(f ?? []))),
	);
}

function pStat(c: any, p: string): Promise<SmbStats> {
	return new Promise((res, rej) => c.stat(p, (e: Error, s: SmbStats) => (e ? rej(e) : res(s))));
}

function pReadFile(c: any, p: string): Promise<Buffer> {
	return new Promise((res, rej) =>
		c.readFile(p, (e: Error, d: Buffer) => (e ? rej(e) : res(d ?? Buffer.alloc(0)))),
	);
}

function pWriteFile(c: any, p: string, d: Buffer): Promise<void> {
	return new Promise((res, rej) => c.writeFile(p, d, (e: Error) => (e ? rej(e) : res())));
}

function pUnlink(c: any, p: string): Promise<void> {
	return new Promise((res, rej) => c.unlink(p, (e: Error) => (e ? rej(e) : res())));
}

function pRename(c: any, a: string, b: string): Promise<void> {
	return new Promise((res, rej) => c.rename(a, b, (e: Error) => (e ? rej(e) : res())));
}

function pMkdir(c: any, p: string): Promise<void> {
	return new Promise((res, rej) => c.mkdir(p, (e: Error) => (e ? rej(e) : res())));
}

function pExists(c: any, p: string): Promise<boolean> {
	return new Promise((res, rej) => c.exists(p, (e: Error, x: boolean) => (e ? rej(e) : res(!!x))));
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Global concurrency limiter. Shared across all recursion levels so the total
 * number of in-flight requests never exceeds `limit` (a per-level limit would
 * multiply with depth).
 */
function createLimiter(limit: number) {
	let active = 0;
	const queue: Array<() => void> = [];
	const next = () => {
		active--;
		const resume = queue.shift();
		if (resume) resume();
	};
	return async function run<T>(fn: () => Promise<T>): Promise<T> {
		if (active >= limit) {
			await new Promise<void>((resolve) => queue.push(resolve));
		}
		active++;
		try {
			return await fn();
		} finally {
			next();
		}
	};
}

function normalizeSmbPath(input: string): string {
	const cleaned = (input || '')
		.replace(/\//g, '\\')
		.replace(/\\+/g, '\\')
		.replace(/^\\+|\\+$/g, '');
	if (cleaned.split('\\').some((seg) => seg === '..')) {
		throw new Error(`Invalid path (".." segments are not allowed): ${input}`);
	}
	return cleaned;
}

function formatSize(bytes: number): string {
	if (!bytes || bytes <= 0) return '0 B';
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
	return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

function toIso(value: number | Date | undefined): string | null {
	if (value === undefined || value === null) return null;
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function friendlyError(err: unknown, context: string): string {
	const msg = (err as Error)?.message ?? String(err);
	const map: Array<[RegExp, string]> = [
		[/STATUS_LOGON_FAILURE|0xc000006d/i, 'Logon failure - check username, password, and domain'],
		[/STATUS_ACCESS_DENIED|0xc0000022/i, 'Access denied - the account has no permission for this path'],
		[/STATUS_BAD_NETWORK_NAME|0xc00000cc/i, 'Share not found - check the share name (include the trailing $ for hidden shares)'],
		[/STATUS_OBJECT_NAME_NOT_FOUND|0xc0000034/i, 'File or folder not found'],
		[/STATUS_OBJECT_PATH_NOT_FOUND|0xc000003a/i, 'Path not found - does the folder exist?'],
		[/STATUS_OBJECT_NAME_COLLISION|0xc0000035/i, 'File or folder already exists'],
		[/STATUS_SHARING_VIOLATION|0xc0000043/i, 'File is locked by another process'],
		[/STATUS_FILE_IS_A_DIRECTORY|0xc00000ba/i, 'The path is a folder, not a file'],
		[/STATUS_ACCOUNT_LOCKED|0xc0000234/i, 'Account is locked'],
		[/STATUS_PASSWORD_EXPIRED|0xc0000071/i, 'Password has expired'],
		[/connect_timeout|ETIMEDOUT/i, 'Connection timeout - is the host reachable on port 445? Check firewalls'],
		[/ECONNREFUSED/i, 'Connection refused - is the SMB service running on port 445?'],
		[/ENOTFOUND|EAI_AGAIN/i, 'Hostname could not be resolved - check DNS or use the IP address'],
	];
	for (const [re, friendly] of map) {
		if (re.test(msg)) return `${context}: ${friendly} (${msg})`;
	}
	return `${context}: ${msg}`;
}

async function withRetry<T>(fn: () => Promise<T>, retries: number, delayMs: number): Promise<T> {
	let lastErr: Error | undefined;
	for (let attempt = 0; attempt <= retries; attempt++) {
		try {
			return await fn();
		} catch (err) {
			lastErr = err as Error;
			const msg = lastErr.message ?? '';
			const transient = /timeout|ETIMEDOUT|ECONNRESET|ECONNREFUSED|EPIPE|socket/i.test(msg);
			if (!transient || attempt === retries) throw lastErr;
			await new Promise((r) => setTimeout(r, delayMs * (attempt + 1)));
		}
	}
	throw lastErr;
}

/* ------------------------------------------------------------------ */
/* Node                                                                */
/* ------------------------------------------------------------------ */

export class SmbPro implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'SMB Pro',
		name: 'smbPro',
		icon: 'fa:folder-open',
		group: ['input'],
		version: 1,
		usableAsTool: true,
		subtitle: '={{$parameter["operation"]}}',
		description:
			'Work with SMB2/SMB3 network shares using NTLMv2: list, upload, download, delete, move files and create folders',
		defaults: {
			name: 'SMB Pro',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'smbApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{ name: 'List Files', value: 'list', description: 'List files and folders', action: 'List files' },
					{ name: 'Upload File', value: 'upload', description: 'Upload binary data as a file', action: 'Upload a file' },
					{ name: 'Download File', value: 'download', description: 'Download a file as binary data', action: 'Download a file' },
					{ name: 'Delete File', value: 'delete', description: 'Delete a file', action: 'Delete a file' },
					{ name: 'Move / Rename', value: 'move', description: 'Move or rename a file', action: 'Move or rename a file' },
					{ name: 'Create Folder', value: 'mkdir', description: 'Create a folder (including intermediate folders)', action: 'Create a folder' },
					{ name: 'Check Exists', value: 'exists', description: 'Check whether a file or folder exists', action: 'Check if a path exists' },
				],
				default: 'list',
			},
			{
				displayName: 'Folder Path',
				name: 'folderPath',
				type: 'string',
				default: '',
				placeholder: 'e.g. subfolder/reports (empty = share root)',
				description: 'Folder inside the share. Forward or backslashes are both accepted.',
				displayOptions: { show: { operation: ['list'] } },
			},
			{
				displayName: 'Include File Stats',
				name: 'includeStats',
				type: 'boolean',
				default: true,
				description: 'Whether to include type, size and timestamps (comes from the directory listing at no extra cost)',
				displayOptions: { show: { operation: ['list'] } },
			},
			{
				displayName: 'Recursive',
				name: 'recursive',
				type: 'boolean',
				default: false,
				description: 'Whether to also descend into subfolders and list their files (folders themselves are not returned)',
				displayOptions: { show: { operation: ['list'] } },
			},
			{
				displayName: 'Max Depth',
				name: 'maxDepth',
				type: 'number',
				default: 0,
				description: 'Maximum recursion depth (0 = unlimited). Only applies when Recursive is enabled.',
				displayOptions: { show: { operation: ['list'], recursive: [true] } },
			},
			{
				displayName: 'Skip Inaccessible Folders',
				name: 'skipInaccessible',
				type: 'boolean',
				default: true,
				description:
					'Whether to skip subfolders the account cannot read instead of failing the whole listing. Skipped folders are reported with an accessDenied flag.',
				displayOptions: { show: { operation: ['list'] } },
			},
			{
				displayName: 'Concurrency',
				name: 'concurrency',
				type: 'number',
				default: 4,
				description:
					'How many subfolders are listed in parallel during a recursive listing. 2-8 is plenty; higher values put more load on the file server.',
				displayOptions: { show: { operation: ['list'] } },
			},
			{
				displayName: 'Binary Property',
				name: 'binaryProperty',
				type: 'string',
				default: 'data',
				required: true,
				description: 'Name of the binary property that contains the file data',
				displayOptions: { show: { operation: ['upload'] } },
			},
			{
				displayName: 'Remote Path',
				name: 'remotePath',
				type: 'string',
				default: '',
				required: true,
				placeholder: 'e.g. subfolder/report.pdf',
				description: 'Target path including the file name, relative to the share root',
				displayOptions: { show: { operation: ['upload'] } },
			},
			{
				displayName: 'Overwrite If Exists',
				name: 'overwrite',
				type: 'boolean',
				default: false,
				displayOptions: { show: { operation: ['upload'] } },
			},
			{
				displayName: 'Create Parent Folders',
				name: 'createParents',
				type: 'boolean',
				default: false,
				description: 'Whether to create missing parent folders automatically',
				displayOptions: { show: { operation: ['upload'] } },
			},
			{
				displayName: 'Remote Path',
				name: 'remotePath',
				type: 'string',
				default: '',
				required: true,
				placeholder: 'e.g. subfolder/report.pdf',
				description: 'Path of the file relative to the share root',
				displayOptions: { show: { operation: ['download'] } },
			},
			{
				displayName: 'Binary Property',
				name: 'binaryProperty',
				type: 'string',
				default: 'data',
				description: 'Name of the binary property to store the downloaded file in',
				displayOptions: { show: { operation: ['download'] } },
			},
			{
				displayName: 'Remote Path',
				name: 'remotePath',
				type: 'string',
				default: '',
				required: true,
				placeholder: 'e.g. subfolder/report.pdf',
				displayOptions: { show: { operation: ['delete'] } },
			},
			{
				displayName: 'Source Path',
				name: 'sourcePath',
				type: 'string',
				default: '',
				required: true,
				placeholder: 'e.g. inbox/invoice.pdf',
				displayOptions: { show: { operation: ['move'] } },
			},
			{
				displayName: 'Target Path',
				name: 'targetPath',
				type: 'string',
				default: '',
				required: true,
				placeholder: 'e.g. archive/invoice.pdf',
				displayOptions: { show: { operation: ['move'] } },
			},
			{
				displayName: 'Overwrite If Exists',
				name: 'overwrite',
				type: 'boolean',
				default: false,
				displayOptions: { show: { operation: ['move'] } },
			},
			{
				displayName: 'Folder Path',
				name: 'folderPath',
				type: 'string',
				default: '',
				required: true,
				placeholder: 'e.g. archive/reports',
				description: 'Folder to create. Missing intermediate folders are created as well.',
				displayOptions: { show: { operation: ['mkdir'] } },
			},
			{
				displayName: 'Remote Path',
				name: 'remotePath',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { operation: ['exists'] } },
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Retries on Transient Errors',
						name: 'retries',
						type: 'number',
						default: 2,
						description: 'Number of retries on timeouts and connection drops (authentication errors are never retried)',
					},
					{
						displayName: 'Retry Delay (ms)',
						name: 'retryDelay',
						type: 'number',
						default: 1000,
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const operation = this.getNodeParameter('operation', 0) as string;

		const credentials = await this.getCredentials('smbApi');
		const host = String(credentials.host ?? '').trim();
		const share = String(credentials.share ?? '')
			.trim()
			.replace(/^[/\\]+|[/\\]+$/g, '');
		const domain = String(credentials.domain ?? '').trim();
		const username = String(credentials.username ?? '').trim();
		const password = String(credentials.password ?? '');
		const timeout = Number(credentials.timeout ?? 15000);

		if (!host || !share || !username) {
			throw new NodeOperationError(
				this.getNode(),
				'Incomplete SMB credentials: host, share, and username are required.',
			);
		}

		const options = this.getNodeParameter('options', 0, {}) as IDataObject;
		const retries = (options.retries as number) ?? 2;
		const retryDelay = (options.retryDelay as number) ?? 1000;

		// One client (= one TCP connection / one SMB session) per node execution.
		const makeClient = () =>
			new SMB2({
				share: `\\\\${host}\\${share}`,
				domain,
				username,
				password,
				autoCloseTimeout: 0,
				connectTimeout: timeout,
			});

		let client: any;

		const ensureFolder = async (c: any, folder: string) => {
			const norm = normalizeSmbPath(folder);
			if (!norm) return;
			const segments = norm.split('\\');
			let current = '';
			for (const seg of segments) {
				current = current ? `${current}\\${seg}` : seg;
				const exists = await pExists(c, current).catch(() => false);
				if (!exists) {
					await pMkdir(c, current).catch((err: Error) => {
						if (!/COLLISION|EEXIST/i.test(err.message)) throw err;
					});
				}
			}
		};

		try {
			client = makeClient();
			const c = client;

			if (operation === 'list') {
				const startPath = normalizeSmbPath(this.getNodeParameter('folderPath', 0, '') as string);
				const includeStats = this.getNodeParameter('includeStats', 0, true) as boolean;
				const recursive = this.getNodeParameter('recursive', 0, false) as boolean;
				const maxDepth = Number(this.getNodeParameter('maxDepth', 0, 0)) || 0;
				const skipInaccessible = this.getNodeParameter('skipInaccessible', 0, true) as boolean;
				const concurrency = Math.max(1, Number(this.getNodeParameter('concurrency', 0, 4)) || 4);
				const isAccessDenied = (err: unknown) =>
					/ACCESS_DENIED|0xc0000022|STATUS_ACCESS_DENIED/i.test((err as Error)?.message ?? '');

				const limit = createLimiter(concurrency);

				const listDir = async (dir: string, depth: number): Promise<void> => {
					let entries: SmbStats[];
					try {
						entries = await limit(() => withRetry(() => pReaddirStats(c, dir), retries, retryDelay));
					} catch (err) {
						if (skipInaccessible && isAccessDenied(err)) {
							returnData.push({
								json: { path: `\\${dir}`, type: 'folder', accessDenied: true, skipped: true },
							});
							return;
						}
						throw new NodeOperationError(this.getNode(), friendlyError(err, `Listing "\\${dir}"`));
					}

					const subdirs: string[] = [];

					for (const s of entries) {
						const name = String(s.name ?? '');
						if (!name) continue;
						const filePath = dir ? `${dir}\\${name}` : name;
						const isDir = typeof s.isDirectory === 'function' && s.isDirectory();
						const canDescend = recursive && isDir && (maxDepth === 0 || depth + 1 <= maxDepth);

						if (canDescend) {
							subdirs.push(filePath);
							continue;
						}

						const entry: IDataObject = { name, path: `\\${filePath}` };
						if (includeStats) {
							entry.type = isDir ? 'folder' : 'file';
							entry.size = isDir ? null : s.size;
							entry.sizeHuman = isDir ? null : formatSize(s.size);
							entry.modified = toIso(s.mtime);
							entry.created = toIso(s.birthtime);
						}
						returnData.push({ json: entry });
					}

					// Subfolders are queued; the shared limiter caps how many are listed at once.
					await Promise.all(subdirs.map((sub) => listDir(sub, depth + 1)));
				};

				await listDir(startPath, 0);

				if (returnData.length === 0) {
					returnData.push({
						json: {
							info: recursive ? 'No files found' : 'Folder is empty',
							path: `\\${startPath}`,
						},
					});
				}
			}

			if (operation === 'upload') {
				for (let i = 0; i < items.length; i++) {
					const binaryProperty = this.getNodeParameter('binaryProperty', i) as string;
					const remotePathRaw = this.getNodeParameter('remotePath', i) as string;
					const overwrite = this.getNodeParameter('overwrite', i, false) as boolean;
					const createParents = this.getNodeParameter('createParents', i, false) as boolean;
					const remotePath = normalizeSmbPath(remotePathRaw);

					if (!remotePath) {
						throw new NodeOperationError(this.getNode(), 'Remote Path must not be empty.', { itemIndex: i });
					}

					this.helpers.assertBinaryData(i, binaryProperty);
					const buffer = await this.helpers.getBinaryDataBuffer(i, binaryProperty);

					if (createParents && remotePath.includes('\\')) {
						const parent = remotePath.substring(0, remotePath.lastIndexOf('\\'));
						await ensureFolder(c, parent);
					}

					const exists = await pExists(c, remotePath).catch(() => false);
					if (exists && !overwrite) {
						throw new NodeOperationError(
							this.getNode(),
							`File already exists: \\${remotePath} (enable Overwrite to replace it)`,
							{ itemIndex: i },
						);
					}
					if (exists && overwrite) {
						await pUnlink(c, remotePath).catch((err) => {
							throw new NodeOperationError(this.getNode(), friendlyError(err, `Overwriting \\${remotePath}`), {
								itemIndex: i,
							});
						});
					}

					await withRetry(() => pWriteFile(c, remotePath, buffer), retries, retryDelay).catch((err) => {
						throw new NodeOperationError(this.getNode(), friendlyError(err, `Uploading to \\${remotePath}`), {
							itemIndex: i,
						});
					});

					returnData.push({
						json: {
							success: true,
							operation: 'upload',
							path: `\\${remotePath}`,
							size: buffer.length,
							sizeHuman: formatSize(buffer.length),
							overwritten: exists && overwrite,
						},
						pairedItem: { item: i },
					});
				}
			}

			if (operation === 'download') {
				for (let i = 0; i < items.length; i++) {
					const remotePath = normalizeSmbPath(this.getNodeParameter('remotePath', i) as string);
					const binaryProperty = this.getNodeParameter('binaryProperty', i, 'data') as string;

					const stat = await pStat(c, remotePath).catch((err) => {
						throw new NodeOperationError(this.getNode(), friendlyError(err, `Downloading \\${remotePath}`), {
							itemIndex: i,
						});
					});
					if (typeof stat.isDirectory === 'function' && stat.isDirectory()) {
						throw new NodeOperationError(this.getNode(), `\\${remotePath} is a folder, not a file.`, { itemIndex: i });
					}

					const buffer = await withRetry(() => pReadFile(c, remotePath), retries, retryDelay).catch((err) => {
						throw new NodeOperationError(this.getNode(), friendlyError(err, `Downloading \\${remotePath}`), {
							itemIndex: i,
						});
					});

					const fileName = remotePath.split('\\').pop() ?? 'download';
					const binaryData = await this.helpers.prepareBinaryData(buffer, fileName);

					returnData.push({
						json: {
							success: true,
							operation: 'download',
							path: `\\${remotePath}`,
							fileName,
							size: buffer.length,
							sizeHuman: formatSize(buffer.length),
						},
						binary: { [binaryProperty]: binaryData },
						pairedItem: { item: i },
					});
				}
			}

			if (operation === 'delete') {
				for (let i = 0; i < items.length; i++) {
					const remotePath = normalizeSmbPath(this.getNodeParameter('remotePath', i) as string);

					const stat = await pStat(c, remotePath).catch((err) => {
						throw new NodeOperationError(this.getNode(), friendlyError(err, `Deleting \\${remotePath}`), {
							itemIndex: i,
						});
					});
					if (typeof stat.isDirectory === 'function' && stat.isDirectory()) {
						throw new NodeOperationError(
							this.getNode(),
							`\\${remotePath} is a folder. This operation only deletes files.`,
							{ itemIndex: i },
						);
					}

					await pUnlink(c, remotePath).catch((err) => {
						throw new NodeOperationError(this.getNode(), friendlyError(err, `Deleting \\${remotePath}`), {
							itemIndex: i,
						});
					});

					returnData.push({
						json: { success: true, operation: 'delete', path: `\\${remotePath}` },
						pairedItem: { item: i },
					});
				}
			}

			if (operation === 'move') {
				for (let i = 0; i < items.length; i++) {
					const sourcePath = normalizeSmbPath(this.getNodeParameter('sourcePath', i) as string);
					const targetPath = normalizeSmbPath(this.getNodeParameter('targetPath', i) as string);
					const overwrite = this.getNodeParameter('overwrite', i, false) as boolean;

					const targetExists = await pExists(c, targetPath).catch(() => false);
					if (targetExists && !overwrite) {
						throw new NodeOperationError(this.getNode(), `Target already exists: \\${targetPath}`, { itemIndex: i });
					}
					if (targetExists && overwrite) {
						await pUnlink(c, targetPath).catch((err) => {
							throw new NodeOperationError(this.getNode(), friendlyError(err, `Overwriting \\${targetPath}`), {
								itemIndex: i,
							});
						});
					}

					await pRename(c, sourcePath, targetPath).catch((err) => {
						throw new NodeOperationError(
							this.getNode(),
							friendlyError(err, `Moving \\${sourcePath} -> \\${targetPath}`),
							{ itemIndex: i },
						);
					});

					returnData.push({
						json: {
							success: true,
							operation: 'move',
							from: `\\${sourcePath}`,
							to: `\\${targetPath}`,
							overwritten: targetExists && overwrite,
						},
						pairedItem: { item: i },
					});
				}
			}

			if (operation === 'mkdir') {
				const folderPath = normalizeSmbPath(this.getNodeParameter('folderPath', 0) as string);
				if (!folderPath) {
					throw new NodeOperationError(this.getNode(), 'Folder Path must not be empty.');
				}
				await ensureFolder(c, folderPath);
				returnData.push({ json: { success: true, operation: 'mkdir', path: `\\${folderPath}` } });
			}

			if (operation === 'exists') {
				for (let i = 0; i < items.length; i++) {
					const remotePath = normalizeSmbPath(this.getNodeParameter('remotePath', i) as string);
					const exists = await pExists(c, remotePath).catch(() => false);
					let type: string | null = null;

					if (exists) {
						try {
							const stat = await pStat(c, remotePath);
							type = typeof stat.isDirectory === 'function' && stat.isDirectory() ? 'folder' : 'file';
						} catch {
							type = 'unknown';
						}
					}

					returnData.push({
						json: { path: `\\${remotePath}`, exists, type },
						pairedItem: { item: i },
					});
				}
			}
		} finally {
			try {
				client?.disconnect();
			} catch {
				// ignore
			}
		}

		return [returnData];
	}
}
