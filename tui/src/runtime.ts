import {existsSync, openSync, readSync, readdirSync, closeSync} from 'node:fs';
import {spawn, type ChildProcess} from 'node:child_process';
import {delimiter, isAbsolute, resolve} from 'node:path';

export interface RunningCommand {
  child: ChildProcess;
  cancel: () => void;
}

const windows = process.platform === 'win32';

export function findExecutable(repoRoot: string, override?: string): string {
  if (override) {
    return isAbsolute(override) ? override : resolve(process.cwd(), override);
  }

  const filename = windows ? 'windissect.exe' : 'windissect';
  const localCandidates = [
    resolve(repoRoot, 'target', 'release', filename),
    resolve(repoRoot, 'target', 'debug', filename),
    resolve(repoRoot, filename),
  ];
  const local = localCandidates.find(candidate => existsSync(candidate));
  if (local) {
    return local;
  }

  for (const directory of (process.env.PATH ?? '').split(delimiter)) {
    const candidate = resolve(directory, filename);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return filename;
}

export function discoverPeFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory, {withFileTypes: true})) {
    if (!entry.isFile()) continue;
    const path = resolve(directory, entry.name);
    let descriptor: number | undefined;
    try {
      descriptor = openSync(path, 'r');
      const magic = Buffer.alloc(2);
      if (readSync(descriptor, magic, 0, 2, 0) === 2 && magic[0] === 0x4D && magic[1] === 0x5A) {
        found.push(path);
      }
    } catch {
      // An unreadable directory entry is not a selectable target.
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
    }
  }
  return found.sort((left, right) => left.localeCompare(right));
}

export function runCommand(
  executable: string,
  args: string[],
  cwd: string,
  onOutput: (channel: 'stdout' | 'stderr', text: string) => void,
  onExit: (code: number | null, signal: NodeJS.Signals | null) => void,
): RunningCommand {
  const child = spawn(executable, args, {
    cwd,
    windowsHide: true,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', text => onOutput('stdout', text));
  child.stderr.on('data', text => onOutput('stderr', text));
  child.on('error', error => onOutput('stderr', `${error.message}\n`));
  child.on('exit', onExit);

  return {
    child,
    cancel: () => {
      if (!child.killed) {
        child.kill('SIGTERM');
      }
    },
  };
}
