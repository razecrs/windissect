export type WorkflowId =
  | 'browse'
  | 'decompile'
  | 'analyze'
  | 'strings'
  | 'extract'
  | 'inventory'
  | 'verify'
  | 'classes'
  | 'emit-headers'
  | 'emit-rust'
  | 'diff';

export type FormValues = Record<string, string>;

export interface FieldDefinition {
  key: string;
  label: string;
  hint: string;
  initial?: string;
  optional?: boolean;
  options?: Array<{label: string; value: string}>;
}

export interface WorkflowDefinition {
  id: WorkflowId;
  label: string;
  description: string;
  accent: string;
  fields: FieldDefinition[];
}

export interface Invocation {
  args: string[];
  summary: string;
}

export const workflows: WorkflowDefinition[] = [
  {
    id: 'browse',
    label: 'Browse functions',
    description: 'Inspect recovered functions, evidence, calls and assembly.',
    accent: 'magenta',
    fields: [
      {key: 'ir', label: 'IR database', hint: 'windissect-work\\challenge\\ir.json'},
      {key: 'binary', label: 'Original binary', hint: 'Needed for per-function C generation', optional: true},
    ],
  },
  {
    id: 'analyze',
    label: 'Analyze everything',
    description: 'Generate IR, strings, assembly, bindings, evidence and docs.',
    accent: 'cyan',
    fields: [
      {key: 'binary', label: 'PE binary', hint: 'challenge.exe'},
      {key: 'pdb', label: 'Matching PDB', hint: 'Optional', optional: true},
      {key: 'out', label: 'Workspace', hint: 'windissect-work\\challenge', optional: true},
    ],
  },
  {
    id: 'decompile',
    label: 'Decompile to C',
    description: 'Generate candidate C-like pseudocode with IDA/Hex-Rays.',
    accent: 'yellow',
    fields: [
      {key: 'binary', label: 'PE binary', hint: 'challenge.exe'},
      {key: 'out', label: 'Pseudocode file', hint: 'pseudocode.c', initial: 'pseudocode.c'},
      {
        key: 'scope',
        label: 'Scope',
        hint: 'Choose which functions to emit',
        initial: 'target',
        options: [
          {label: 'Main / target code     main and reachable user logic', value: 'target'},
          {label: 'All functions          include compiler and runtime code', value: 'all'},
          {label: 'Helpers only           compiler/runtime helpers', value: 'helpers'},
        ],
      },
      {key: 'ida', label: 'IDA idat path', hint: 'Optional; auto-detected', optional: true},
    ],
  },
  {
    id: 'strings',
    label: 'Search strings',
    description: 'Find ASCII/UTF-16LE text with file offsets and PE RVAs.',
    accent: 'green',
    fields: [
      {key: 'binary', label: 'Binary', hint: 'challenge.exe'},
      {key: 'query', label: 'Contains', hint: 'Optional, e.g. flag{', optional: true},
      {key: 'min', label: 'Minimum length', hint: '4', initial: '4'},
      {key: 'encoding', label: 'Encoding', hint: 'all, ascii, or utf16', initial: 'all'},
      {key: 'limit', label: 'Result limit', hint: '200; zero is unlimited', initial: '200'},
    ],
  },
  {
    id: 'extract',
    label: 'Extract binary',
    description: 'Build IR from a PE, optionally anchored by its matching PDB.',
    accent: 'cyan',
    fields: [
      {key: 'dll', label: 'PE binary', hint: 'C:\\Windows\\System32\\dwmapi.dll'},
      {key: 'pdb', label: 'Matching PDB', hint: 'Leave blank for PE-only recovery', optional: true},
      {key: 'out', label: 'Output IR', hint: 'ir\\dwmapi.json', initial: 'ir\\symbols.json'},
    ],
  },
  {
    id: 'inventory',
    label: 'Exhaustive inventory',
    description: 'Collect resumable PE/PDB observations with pgressive mode.',
    accent: 'magenta',
    fields: [
      {key: 'dll', label: 'PE binary', hint: 'C:\\Windows\\System32\\dwmapi.dll'},
      {key: 'pdb', label: 'Matching PDB', hint: 'Optional', optional: true},
      {key: 'out', label: 'Inventory root', hint: 'pgressive\\dwmapi', initial: 'pgressive'},
    ],
  },
  {
    id: 'verify',
    label: 'Verify IR',
    description: 'Check invariants and optional target-specific golden facts.',
    accent: 'green',
    fields: [
      {key: 'ir', label: 'IR database', hint: 'ir\\symbols.json', initial: 'ir\\symbols.json'},
      {key: 'profile', label: 'Golden profile', hint: 'Optional, e.g. dui70', optional: true},
    ],
  },
  {
    id: 'classes',
    label: 'Browse classes',
    description: 'List recovered classes ordered by member count.',
    accent: 'blue',
    fields: [
      {key: 'ir', label: 'IR database', hint: 'ir\\symbols.json', initial: 'ir\\symbols.json'},
    ],
  },
  {
    id: 'emit-headers',
    label: 'Generate C/C++',
    description: 'Emit verified headers with candidates kept separate.',
    accent: 'yellow',
    fields: [
      {key: 'ir', label: 'IR database', hint: 'ir\\symbols.json', initial: 'ir\\symbols.json'},
      {key: 'out', label: 'Header directory', hint: 'headers', initial: 'headers'},
    ],
  },
  {
    id: 'emit-rust',
    label: 'Generate Rust FFI',
    description: 'Emit a buildable proof-gated Rust crate.',
    accent: 'red',
    fields: [
      {key: 'ir', label: 'IR database', hint: 'ir\\symbols.json', initial: 'ir\\symbols.json'},
      {key: 'out', label: 'Crate directory', hint: 'rust', initial: 'rust'},
    ],
  },
  {
    id: 'diff',
    label: 'Diff two builds',
    description: 'Compare symbol, signature, implementation and call-graph changes.',
    accent: 'cyan',
    fields: [
      {key: 'old', label: 'Old IR', hint: 'ir\\old.json'},
      {key: 'new', label: 'New IR', hint: 'ir\\new.json'},
      {key: 'json', label: 'JSON report', hint: 'changes.json', optional: true},
      {key: 'markdown', label: 'Markdown report', hint: 'changes.md', optional: true},
    ],
  },
];

const pushOption = (args: string[], flag: string, value: string | undefined): void => {
  if (value?.trim()) {
    args.push(flag, value.trim());
  }
};

export function buildInvocation(workflow: WorkflowId, values: FormValues): Invocation {
  switch (workflow) {
    case 'browse':
      return {args: ['classes', '--ir', values.ir], summary: 'Browse recovered functions'};
    case 'decompile': {
      const args = ['decompile', values.binary, '--out', values.out, '--scope', values.scope];
      pushOption(args, '--ida', values.ida);
      return {args, summary: 'Generate candidate C-like pseudocode from machine code'};
    }
    case 'analyze': {
      const args = ['analyze', values.binary];
      pushOption(args, '--pdb', values.pdb);
      pushOption(args, '--out', values.out);
      return {args, summary: 'Build a complete browsable analysis workspace'};
    }
    case 'strings': {
      const args = [
        'strings', values.binary,
        '--min-length', values.min,
        '--encoding', values.encoding,
        '--limit', values.limit,
      ];
      if (values.query?.trim()) args.splice(2, 0, values.query.trim());
      return {args, summary: 'Search binary strings and map them to PE RVAs'};
    }
    case 'extract': {
      const args = ['extract', values.dll, '--out', values.out];
      pushOption(args, '--pdb', values.pdb);
      return {args, summary: 'Extract PE/PDB evidence into trustworthy IR'};
    }
    case 'inventory': {
      const args = ['pgressive', values.dll, '--out', values.out];
      pushOption(args, '--pdb', values.pdb);
      return {args, summary: 'Build an exhaustive resumable inventory'};
    }
    case 'verify': {
      const args = ['verify', '--ir', values.ir];
      pushOption(args, '--profile', values.profile);
      return {args, summary: 'Verify IR invariants and golden checks'};
    }
    case 'classes':
      return {args: ['classes', '--ir', values.ir], summary: 'Browse recovered classes'};
    case 'emit-headers':
      return {
        args: ['emit-headers', '--ir', values.ir, '--out', values.out],
        summary: 'Generate proof-gated C and C++ headers',
      };
    case 'emit-rust':
      return {
        args: ['emit-rust', '--ir', values.ir, '--out', values.out],
        summary: 'Generate a proof-gated Rust FFI crate',
      };
    case 'diff': {
      const args = ['diff', values.old, values.new];
      pushOption(args, '--json-out', values.json);
      pushOption(args, '--markdown-out', values.markdown);
      return {args, summary: 'Compare two build-anchored IR databases'};
    }
  }
}

export function missingRequiredFields(
  workflow: WorkflowDefinition,
  values: FormValues,
): FieldDefinition[] {
  return workflow.fields.filter(field => !field.optional && !values[field.key]?.trim());
}

export function displayCommand(executable: string, args: string[]): string {
  const quote = (value: string): string =>
    /[\s"]/u.test(value) ? `"${value.replaceAll('"', '\\"')}"` : value;
  return [executable, ...args].map(quote).join(' ');
}
