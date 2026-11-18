#!/usr/bin/env node
import React, {useEffect, useMemo, useRef, useState} from 'react';
import {Box, Newline, Text, render, useApp, useInput, useStdout} from 'ink';
import SelectInput from 'ink-select-input';
import TextInput from 'ink-text-input';
import {existsSync, readFileSync} from 'node:fs';
import {basename, dirname, extname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  buildInvocation,
  displayCommand,
  missingRequiredFields,
  workflows,
  type FormValues,
  type WorkflowDefinition,
  type WorkflowId,
} from './commands.js';
import {discoverPeFiles, findExecutable, runCommand, type RunningCommand} from './runtime.js';
import {helperReason} from './triage.js';

type Screen = 'picker' | 'menu' | 'form' | 'preview' | 'running' | 'result' | 'browser' | 'function' | 'viewer' | 'strings';
type RunStatus = 'idle' | 'running' | 'passed' | 'failed' | 'cancelled';

interface StaticDataReference {rva: number; virtual_address: number; section: string; file_offset: number; inferred_size?: number; size_source?: string; size_evidence_rva?: number; bytes: string; preview_size: number; truncated: boolean}
interface IrInstruction {rva: number; length?: number; text: string; flow: string; branch_target_rva?: number; memory_target_rva?: number; data_reference?: StaticDataReference}
interface IrEdge {from_rva: number; to_rva: number; kind: string}
interface IrFunction {rva: number; size: number; instructions?: IrInstruction[]; cfg_edges?: IrEdge[]; symbol_ids?: string[]}
interface IrSymbol {
  id: string;
  demangled?: string;
  rva: number;
  size: number;
  is_code: boolean;
  library?: boolean;
  kind?: string;
  provenance: string;
  confidence: string;
  calls?: string[];
  callers?: string[];
  imports?: string[];
}
interface IrDatabase {binary?: {file?: string; entry_point_rva?: number}; symbols: IrSymbol[]; functions?: IrFunction[]; capabilities?: Array<{id: string; status: string}>}
interface StringMatch {offset: number; rva?: number; encoding: string; byteLength: number; text: string}
interface StringReference {func: IrFunction; instruction: IrInstruction}

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(packageRoot, '..');
const workspaceRoot = process.cwd();
const overrideIndex = process.argv.indexOf('--bin');
const binaryOverride = overrideIndex >= 0 ? process.argv[overrideIndex + 1] : process.env.WINDISSECT_BIN;

const statusColor = (status: RunStatus): string => {
  switch (status) {
    case 'running': return 'yellow';
    case 'passed': return 'green';
    case 'failed': return 'red';
    case 'cancelled': return 'magenta';
    default: return 'gray';
  }
};

function parseStringTable(output: string): StringMatch[] {
  const pattern = /^0x([0-9A-F]+)\s+(0x[0-9A-F]+|—)\s+(ascii|utf16le)\s+(.*)$/iu;
  return output.replaceAll('\r\n', '\n').split('\n').flatMap(line => {
    const match = pattern.exec(line.trim());
    if (!match) return [];
    const text = match[4].replaceAll('\\r', '\r').replaceAll('\\n', '\n').replaceAll('\\t', '\t').replaceAll('\\\\', '\\');
    return [{
      offset: Number.parseInt(match[1], 16),
      rva: match[2] === '—' ? undefined : Number.parseInt(match[2].slice(2), 16),
      encoding: match[3],
      byteLength: text.length * (match[3] === 'utf16le' ? 2 : 1),
      text,
    }];
  });
}

function Header({binary, status}: {binary: string; status: RunStatus}) {
  return (
    <Box borderStyle="round" borderColor="cyan" paddingX={1} flexDirection="column">
      <Box justifyContent="space-between">
        <Box>
          <Text bold color="cyan">WINDISSECT</Text>
          <Text dimColor>  evidence workbench</Text>
        </Box>
        <Box>
          <Text dimColor>{binary}  </Text>
          <Text bold color={statusColor(status)}>● {status.toUpperCase()}</Text>
        </Box>
      </Box>
      <Text dimColor>workspace  {workspaceRoot}</Text>
    </Box>
  );
}

function Footer({screen}: {screen: Screen}) {
  const help = screen === 'picker'
    ? '↑↓ choose  enter open  q quit'
    : screen === 'menu'
    ? '↑↓ choose  enter open  o change target  q quit'
    : screen === 'form'
      ? 'enter next  esc back  ctrl+c quit'
      : screen === 'preview'
        ? 'enter run  esc edit  ctrl+c quit'
        : screen === 'running'
          ? 'ctrl+c cancel'
          : screen === 'browser'
            ? '↑↓ select  enter inspect  c candidates/all  h helpers  esc menu'
            : screen === 'strings'
              ? '↑↓ string  x next reference  enter open function  esc menu  q quit'
            : screen === 'function'
              ? 'd generate C  esc function list  q quit'
          : screen === 'viewer'
            ? '↑↓ scroll  page up/down  esc back  q quit'
            : 'enter menu  r rerun  b browse functions  v view pseudocode  q quit';
  return <Box marginTop={1}><Text dimColor>{help}</Text></Box>;
}

function TargetPicker({files, onSelect}: {files: string[]; onSelect: (path?: string) => void}) {
  const items = [
    ...files.map(path => ({label: path, value: path})),
    {label: 'Continue without a preselected target', value: ''},
  ];
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text bold>Select a PE from the current directory</Text>
      <Text dimColor>Windissect checked the MZ signature, not just the filename extension.</Text>
      <Box marginTop={1} marginLeft={1}>
        <SelectInput items={items} onSelect={item => onSelect(item.value || undefined)} />
      </Box>
    </Box>
  );
}

function Menu({target, onSelect}: {target?: string; onSelect: (workflow: WorkflowDefinition) => void}) {
  const items = workflows.map(workflow => ({
    label: `${workflow.label.padEnd(21)} ${workflow.description}`,
    value: workflow.id,
  }));
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text><Text dimColor>Target  </Text>{target ?? 'not selected'}</Text>
      <Text bold>Choose a workflow</Text>
      <Box marginTop={1} marginLeft={1}>
        <SelectInput
          items={items}
          onSelect={item => onSelect(workflows.find(workflow => workflow.id === item.value)!)}
        />
      </Box>
      <Box marginTop={1} borderStyle="single" borderColor="gray" paddingX={1}>
        <Text dimColor>Verified facts stay separate from candidates in every generated artifact.</Text>
      </Box>
    </Box>
  );
}

function Form({
  workflow,
  values,
  setValues,
  onComplete,
  onBack,
}: {
  workflow: WorkflowDefinition;
  values: FormValues;
  setValues: React.Dispatch<React.SetStateAction<FormValues>>;
  onComplete: () => void;
  onBack: () => void;
}) {
  const [index, setIndex] = useState(0);
  const field = workflow.fields[index];
  const [error, setError] = useState('');

  useInput((_input, key) => {
    if (key.escape) {
      if (index === 0) onBack();
      else {
        setError('');
        setIndex(current => current - 1);
      }
    }
  });

  const submit = (selectedValue?: string): void => {
    const value = selectedValue?.trim() ?? values[field.key]?.trim() ?? '';
    if (!field.optional && !value) {
      setError(`${field.label} is required`);
      return;
    }
    setError('');
    if (index + 1 < workflow.fields.length) {
      setIndex(current => current + 1);
    } else {
      const missing = missingRequiredFields(workflow, values);
      if (missing.length) setError(`${missing[0].label} is required`);
      else onComplete();
    }
  };

  return (
    <Box flexDirection="column" marginTop={1}>
      <Box justifyContent="space-between">
        <Text bold color={workflow.accent}>{workflow.label}</Text>
        <Text dimColor>{index + 1}/{workflow.fields.length}</Text>
      </Box>
      <Text dimColor>{workflow.description}</Text>
      <Box marginTop={1} flexDirection="column" borderStyle="round" borderColor={workflow.accent} paddingX={1}>
        <Text bold>{field.label}{field.optional ? <Text dimColor>  optional</Text> : null}</Text>
        {field.options ? (
          <Box marginLeft={1}>
            <SelectInput
              items={field.options}
              initialIndex={Math.max(0, field.options.findIndex(option => option.value === values[field.key]))}
              onSelect={item => {
                setValues(current => ({...current, [field.key]: item.value}));
                submit(item.value);
              }}
            />
          </Box>
        ) : (
          <Box>
            <Text color={workflow.accent}>› </Text>
            <TextInput
              value={values[field.key] ?? ''}
              placeholder={field.hint}
              onChange={value => setValues(current => ({...current, [field.key]: value}))}
              onSubmit={() => submit()}
            />
          </Box>
        )}
        {error ? <Text color="red">{error}</Text> : <Text dimColor>{field.options ? 'Use ↑↓ and Enter' : 'Press Enter to continue'}</Text>}
      </Box>
      <Box marginTop={1} flexDirection="column">
        {workflow.fields.map((item, itemIndex) => (
          <Text key={item.key} dimColor={itemIndex !== index}>
            {itemIndex < index ? '✓' : itemIndex === index ? '●' : '○'} {item.label}: {values[item.key] || '—'}
          </Text>
        ))}
      </Box>
    </Box>
  );
}

function FunctionBrowser({
  database,
  candidateOnly,
  hideHelpers,
  selected,
  onHighlight,
  onSelect,
}: {
  database: IrDatabase;
  candidateOnly: boolean;
  hideHelpers: boolean;
  selected?: IrSymbol;
  onHighlight: (symbol: IrSymbol) => void;
  onSelect: (symbol: IrSymbol) => void;
}) {
  const symbols = database.symbols
    .filter(symbol => symbol.is_code)
    .filter(symbol => !candidateOnly || symbol.confidence !== 'certain')
    .filter(symbol => !hideHelpers || !helperReason(symbol))
    .sort((left, right) => left.rva - right.rva);
  const items = symbols.map(symbol => ({
    value: symbol.id,
    label: `${helperReason(symbol) ? 'H' : symbol.confidence === 'certain' ? 'V' : 'C'}  0x${symbol.rva.toString(16).toUpperCase().padStart(8, '0')}  ${(symbol.demangled ?? symbol.id).slice(0, 72)}`,
  }));
  return (
    <Box flexDirection="column" marginTop={1}>
      <Box justifyContent="space-between">
        <Text bold color="magenta">RECOVERED FUNCTIONS</Text>
        <Text>{candidateOnly ? 'candidates' : 'all'} · {hideHelpers ? 'helpers hidden' : 'helpers shown'}  {symbols.length}/{database.symbols.filter(symbol => symbol.is_code).length}</Text>
      </Box>
      <Text dimColor>V = certain evidence  C = candidate inference  H = probable compiler/library helper</Text>
      <Box marginTop={1} borderStyle="round" borderColor="magenta" paddingX={1} flexGrow={1}>
        {items.length
          ? <SelectInput
              items={items}
              limit={18}
              initialIndex={Math.max(0, items.findIndex(item => item.value === selected?.id))}
              onHighlight={item => onHighlight(symbols.find(symbol => symbol.id === item.value)!)}
              onSelect={item => onSelect(symbols.find(symbol => symbol.id === item.value)!)}
            />
          : <Text dimColor>No functions in this view. Press c to show all.</Text>}
      </Box>
    </Box>
  );
}

function FunctionPreview({symbol, analysis}: {symbol?: IrSymbol; analysis?: IrFunction}) {
  if (!symbol) return <Box paddingX={1}><Text dimColor>Select a function to inspect its evidence.</Text></Box>;
  const instructions = analysis?.instructions ?? [];
  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold color={symbol.confidence === 'certain' ? 'green' : 'yellow'} wrap="truncate-end">
        {symbol.demangled ?? symbol.id}
      </Text>
      <Text dimColor>RVA 0x{symbol.rva.toString(16).toUpperCase().padStart(8, '0')} · {symbol.size} bytes</Text>
      <Text><Text dimColor>Evidence  </Text>{symbol.provenance}</Text>
      <Text><Text dimColor>Status    </Text>{symbol.confidence === 'certain' ? 'verified/certain' : 'candidate'}</Text>
      {helperReason(symbol) && <Text color="yellow">Helper: {helperReason(symbol)}</Text>}
      <Box marginTop={1} flexDirection="column">
        <Text bold color="cyan">CALLS</Text>
        {(symbol.calls ?? []).slice(0, 5).map(value => <Text key={value} wrap="truncate-end">→ {value}</Text>)}
        {!(symbol.calls?.length) && <Text dimColor>—</Text>}
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text bold color="cyan">IMPORTS</Text>
        {(symbol.imports ?? []).slice(0, 4).map(value => <Text key={value} wrap="truncate-end">↗ {value}</Text>)}
        {!(symbol.imports?.length) && <Text dimColor>—</Text>}
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text bold color="blue">ASSEMBLY PREVIEW</Text>
        {instructions.slice(0, 9).map(instruction => (
          <Text key={`${instruction.rva}-${instruction.text}`} wrap="truncate-end">
            <Text dimColor>{instruction.rva.toString(16).toUpperCase().padStart(8, '0')}  </Text>{instruction.text}
          </Text>
        ))}
        {!instructions.length && <Text dimColor>No retained instructions.</Text>}
      </Box>
      <Box marginTop={1}><Text color="magenta">Enter opens full function · d available there</Text></Box>
    </Box>
  );
}

function referencesForString(database: IrDatabase | null, match?: StringMatch): StringReference[] {
  if (!database || match?.rva === undefined) return [];
  const start = match.rva;
  const end = start + Math.max(1, match.byteLength);
  return (database.functions ?? []).flatMap(func => (func.instructions ?? [])
    .filter(instruction => instruction.memory_target_rva !== undefined
      && instruction.memory_target_rva >= start
      && instruction.memory_target_rva < end)
    .map(instruction => ({func, instruction})));
}

function StringExplorer({matches, database, selected, referenceIndex, onHighlight, onOpen}: {
  matches: StringMatch[];
  database: IrDatabase | null;
  selected?: StringMatch;
  referenceIndex: number;
  onHighlight: (match: StringMatch) => void;
  onOpen: (match: StringMatch) => void;
}) {
  const references = referencesForString(database, selected);
  const reference = references.length ? references[referenceIndex % references.length] : undefined;
  const instructions = reference?.func.instructions ?? [];
  const at = reference ? instructions.findIndex(item => item.rva === reference.instruction.rva) : -1;
  const around = at >= 0 ? instructions.slice(Math.max(0, at - 6), at + 7) : [];
  const symbol = reference && database?.symbols.find(item => item.rva === reference.func.rva);
  const nearbyRvas = new Set(around.map(instruction => instruction.rva));
  const localEdges = reference?.func.cfg_edges?.filter(edge =>
    nearbyRvas.has(edge.from_rva) || nearbyRvas.has(edge.to_rva)) ?? [];
  const items = matches.map((match, index) => ({
    value: index,
    label: `${match.rva === undefined ? '—'.padEnd(10) : `0x${match.rva.toString(16).toUpperCase().padStart(8, '0')}`}  ${match.text.slice(0, 48)}`,
  }));
  return (
    <Box marginTop={1}>
      <Box width="43%" flexDirection="column" paddingRight={1}>
        <Box justifyContent="space-between"><Text bold color="green">STRINGS</Text><Text>{matches.length} matches</Text></Box>
        <Text dimColor>Select a string to resolve machine-code references.</Text>
        <Box marginTop={1} borderStyle="round" borderColor="green" paddingX={1}>
          <SelectInput items={items} limit={18} onHighlight={item => onHighlight(matches[item.value])} onSelect={item => onOpen(matches[item.value])} />
        </Box>
      </Box>
      <Box width="57%" flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1}>
        <Text bold color="green" wrap="truncate-end">{selected?.text ?? 'Select a string'}</Text>
        {selected && <Text dimColor>file 0x{selected.offset.toString(16).toUpperCase().padStart(8, '0')} · RVA {selected.rva === undefined ? 'unmapped' : `0x${selected.rva.toString(16).toUpperCase().padStart(8, '0')}`} · {selected.encoding}</Text>}
        {reference ? <>
          <Box marginTop={1} justifyContent="space-between">
            <Text><Text dimColor>Referenced by  </Text>{symbol?.demangled ?? symbol?.id ?? reference.func.symbol_ids?.[0] ?? `sub_${reference.func.rva.toString(16)}`}</Text>
            <Text color="cyan">xref {referenceIndex % references.length + 1}/{references.length}</Text>
          </Box>
          <Text dimColor>instruction RVA 0x{reference.instruction.rva.toString(16).toUpperCase().padStart(8, '0')}</Text>
          {reference.instruction.data_reference && (
            <Box marginTop={1} flexDirection="column" borderStyle="single" borderColor="magenta" paddingX={1}>
              <Text bold color="magenta">REFERENCED STATIC DATA</Text>
              <Text>VA 0x{reference.instruction.data_reference.virtual_address.toString(16).toUpperCase()} · RVA 0x{reference.instruction.data_reference.rva.toString(16).toUpperCase().padStart(8, '0')}</Text>
              <Text>section {reference.instruction.data_reference.section} · file 0x{reference.instruction.data_reference.file_offset.toString(16).toUpperCase()}</Text>
              {reference.instruction.data_reference.inferred_size !== undefined
                ? <Text color="green">size {reference.instruction.data_reference.inferred_size} bytes · {reference.instruction.data_reference.size_source} · evidence 0x{reference.instruction.data_reference.size_evidence_rva?.toString(16).toUpperCase()}</Text>
                : <Text color="yellow">{reference.instruction.data_reference.preview_size}-byte bounded preview; object size unresolved</Text>}
              <Text wrap="wrap">{reference.instruction.data_reference.bytes}{reference.instruction.data_reference.truncated ? ' …' : ''}</Text>
            </Box>
          )}
          <Box marginTop={1} flexDirection="column">
            <Text bold color="blue">CODE AROUND REFERENCE</Text>
            {around.map(instruction => (
              <Text key={instruction.rva} color={instruction.rva === reference.instruction.rva ? 'green' : undefined} wrap="truncate-end">
                {instruction.rva === reference.instruction.rva ? '▶ ' : '  '}
                <Text dimColor>{instruction.rva.toString(16).toUpperCase().padStart(8, '0')}  </Text>{instruction.text}
                {instruction.branch_target_rva !== undefined ? <Text color="yellow">  → 0x{instruction.branch_target_rva.toString(16).toUpperCase()}</Text> : null}
              </Text>
            ))}
          </Box>
          <Box marginTop={1} flexDirection="column">
            <Text bold color="yellow">LOCAL CONTROL FLOW</Text>
            {localEdges.map((edge, index) => <Text key={`${edge.from_rva}-${edge.to_rva}-${index}`}>0x{edge.from_rva.toString(16).toUpperCase()} → 0x{edge.to_rva.toString(16).toUpperCase()} <Text dimColor>{edge.kind}</Text></Text>)}
            {!localEdges.length && <Text dimColor>No recorded jump crosses the displayed instruction window.</Text>}
          </Box>
          <Text color="green">Enter opens the complete containing function.</Text>
        </> : selected ? <Box marginTop={1}><Text color="yellow">No decoded direct reference was found in the current instruction index.</Text></Box> : null}
      </Box>
    </Box>
  );
}

function FunctionDetail({symbol, analysis}: {symbol: IrSymbol; analysis?: IrFunction}) {
  const instructions = analysis?.instructions ?? [];
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text bold color={symbol.confidence === 'certain' ? 'green' : 'yellow'}>
        {symbol.demangled ?? symbol.id}
      </Text>
      <Text>RVA 0x{symbol.rva.toString(16).toUpperCase().padStart(8, '0')}  size {symbol.size}  {symbol.provenance}  {symbol.confidence}</Text>
      {helperReason(symbol) && <Text color="yellow">Auto-triage: probable helper — {helperReason(symbol)}</Text>}
      <Box marginTop={1}>
        <Box width="50%" flexDirection="column">
          <Text bold>Calls</Text>
          {(symbol.calls ?? []).slice(0, 8).map(value => <Text key={value} dimColor>→ {value}</Text>)}
          {!(symbol.calls?.length) && <Text dimColor>—</Text>}
        </Box>
        <Box width="50%" flexDirection="column">
          <Text bold>Imports</Text>
          {(symbol.imports ?? []).slice(0, 8).map(value => <Text key={value} dimColor>↗ {value}</Text>)}
          {!(symbol.imports?.length) && <Text dimColor>—</Text>}
        </Box>
      </Box>
      <Box marginTop={1} borderStyle="round" borderColor="blue" paddingX={1} flexDirection="column">
        <Text bold>Assembly</Text>
        {instructions.slice(0, 18).map(instruction => (
          <Box key={`${instruction.rva}-${instruction.text}`} flexDirection="column">
            <Text>
              <Text dimColor>{instruction.rva.toString(16).toUpperCase().padStart(8, '0')}  </Text>{instruction.text}
            </Text>
            {instruction.data_reference && <Text color="magenta" wrap="wrap">
              ↳ {instruction.data_reference.section} RVA 0x{instruction.data_reference.rva.toString(16).toUpperCase()} · {instruction.data_reference.inferred_size !== undefined ? `${instruction.data_reference.inferred_size} proven bytes` : `${instruction.data_reference.preview_size}-byte preview`} · {instruction.data_reference.bytes}{instruction.data_reference.truncated ? ' …' : ''}
            </Text>}
          </Box>
        ))}
        {!instructions.length && <Text dimColor>Instruction records were compacted; rerun Analyze everything to retain them.</Text>}
      </Box>
      <Text color="yellow">Press d to generate candidate C for this function.</Text>
    </Box>
  );
}

function App() {
  const {exit} = useApp();
  const {stdout} = useStdout();
  const discoveredFiles = useMemo(() => discoverPeFiles(process.cwd()), []);
  const [screen, setScreen] = useState<Screen>('picker');
  const [target, setTarget] = useState<string | undefined>();
  const [workflow, setWorkflow] = useState<WorkflowDefinition>(workflows[0]);
  const [values, setValues] = useState<FormValues>({});
  const [lines, setLines] = useState<string[]>([]);
  const [status, setStatus] = useState<RunStatus>('idle');
  const [exitCode, setExitCode] = useState<number | null>(null);
  const [artifact, setArtifact] = useState<{path: string; lines: string[]} | null>(null);
  const [artifactOffset, setArtifactOffset] = useState(0);
  const [viewerReturn, setViewerReturn] = useState<Screen>('result');
  const [database, setDatabase] = useState<IrDatabase | null>(null);
  const [databasePath, setDatabasePath] = useState<string>();
  const [candidateOnly, setCandidateOnly] = useState(false);
  const [hideHelpers, setHideHelpers] = useState(true);
  const [selectedSymbol, setSelectedSymbol] = useState<IrSymbol>();
  const [functionReturn, setFunctionReturn] = useState<Screen>('browser');
  const [stringMatches, setStringMatches] = useState<StringMatch[]>([]);
  const [selectedString, setSelectedString] = useState<StringMatch>();
  const [stringReferenceIndex, setStringReferenceIndex] = useState(0);
  const [runSummary, setRunSummary] = useState('');
  const running = useRef<RunningCommand | null>(null);
  const commandStdout = useRef('');
  const executable = useMemo(() => findExecutable(repoRoot, binaryOverride), []);
  const invocation = useMemo(() => buildInvocation(workflow.id, values), [workflow.id, values]);

  const chooseWorkflow = (selected: WorkflowDefinition): void => {
    const initial = Object.fromEntries(selected.fields.map(field => [field.key, field.initial ?? '']));
    if (target) {
      if ('binary' in initial) initial.binary = target;
      if ('dll' in initial) initial.dll = target;
      const extension = extname(target);
      const stem = basename(target, extension) || 'binary';
      const workspace = resolve(process.cwd(), 'windissect-work', stem);
      if (selected.id === 'analyze') initial.out = workspace;
      if (selected.id === 'decompile') initial.out = join(workspace, 'pseudocode.c');
    }
    setWorkflow(selected);
    setValues(initial);
    setStatus('idle');
    setLines([]);
    setScreen('form');
  };

  const readDatabase = (path: string): IrDatabase => {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as IrDatabase;
    if (!Array.isArray(parsed.symbols)) throw new Error('IR has no symbol inventory');
    return parsed;
  };

  const prepareStringExplorer = (matches: StringMatch[]): void => {
    setStringMatches(matches);
    setSelectedString(matches[0]);
    setStringReferenceIndex(0);
    const binary = resolve(workspaceRoot, values.binary);
    const stem = basename(binary, extname(binary)) || 'binary';
    const candidates = [
      resolve(workspaceRoot, 'windissect-work', stem, 'ir.json'),
      resolve(workspaceRoot, '.windissect', 'cache', stem, 'ir.json'),
    ];
    const usable = candidates.find(path => {
      if (!existsSync(path)) return false;
      try {
        const cached = readDatabase(path);
        return (cached.functions ?? []).some(func => (func.instructions?.length ?? 0) > 0)
          && (cached.capabilities ?? []).some(capability => capability.id === 'resolved-static-data');
      } catch {
        return false;
      }
    });
    if (usable) {
      setDatabase(readDatabase(usable));
      setDatabasePath(usable);
      setScreen('strings');
      return;
    }

    const out = candidates[1];
    const args = ['extract', binary, '--out', out, '--retain-instructions'];
    setRunSummary('Build string cross-reference index');
    setLines(current => [...current, '', `$ ${displayCommand(executable, args)}`, '', 'Indexing instructions, data references, jumps and CFG edges…']);
    setStatus('running');
    setScreen('running');
    running.current = runCommand(executable, args, workspaceRoot,
      (channel, text) => setLines(current => [...current, ...text.replaceAll('\r\n', '\n').split('\n').filter(Boolean).map(line => channel === 'stderr' ? `! ${line}` : line)].slice(-1000)),
      (code, signal) => {
        running.current = null;
        setExitCode(code);
        setStatus(signal ? 'cancelled' : code === 0 ? 'passed' : 'failed');
        if (code === 0 && !signal) {
          try {
            setDatabase(readDatabase(out));
            setDatabasePath(out);
            setScreen('strings');
          } catch (error) {
            setLines(current => [...current, `! ${error instanceof Error ? error.message : String(error)}`]);
            setScreen('result');
          }
        } else setScreen('result');
      });
  };

  const start = (): void => {
    setRunSummary(invocation.summary);
    setLines([`$ ${displayCommand(executable, invocation.args)}`, '']);
    setStatus('running');
    setExitCode(null);
    commandStdout.current = '';
    setScreen('running');
    running.current = runCommand(
      executable,
      invocation.args,
      workspaceRoot,
      (channel, text) => {
        if (channel === 'stdout') commandStdout.current += text;
        const incoming = text.replaceAll('\r\n', '\n').split('\n');
        if (incoming.at(-1) === '') incoming.pop();
        setLines(current => [...current, ...incoming.map(line => channel === 'stderr' ? `! ${line}` : line)].slice(-1000));
      },
      (code, signal) => {
        running.current = null;
        setExitCode(code);
        setStatus(signal ? 'cancelled' : code === 0 ? 'passed' : 'failed');
        const ir = workflow.id === 'analyze' && code === 0 && !signal ? analyzedIrPath() : undefined;
        if (workflow.id === 'strings' && code === 0 && !signal) prepareStringExplorer(parseStringTable(commandStdout.current));
        else if (ir) openDatabase(ir);
        else setScreen('result');
      },
    );
  };

  const openDatabase = (path: string): void => {
    try {
      const absolute = resolve(workspaceRoot, path);
      const parsed = readDatabase(absolute);
      setDatabase(parsed);
      setDatabasePath(absolute);
      setCandidateOnly(false);
      setHideHelpers(true);
      setScreen('browser');
    } catch (error) {
      setLines([`! ${error instanceof Error ? error.message : String(error)}`]);
      setStatus('failed');
      setScreen('result');
    }
  };

  const analyzedIrPath = (): string | undefined => {
    if (workflow.id === 'browse') return values.ir;
    if (workflow.id === 'extract') return values.out;
    if (workflow.id !== 'analyze') return undefined;
    const extension = extname(values.binary);
    const stem = basename(values.binary, extension) || 'binary';
    return join(values.out?.trim() || join('windissect-work', stem), 'ir.json');
  };

  const decompileSelected = (): void => {
    if (!selectedSymbol || !target) {
      setLines(['! Select the original binary before generating per-function C.']);
      setStatus('failed');
      setScreen('result');
      return;
    }
    const out = join('.windissect', 'pseudocode', `sub_${selectedSymbol.rva.toString(16).padStart(8, '0')}.c`);
    const args = ['decompile', target, '--rva', `0x${selectedSymbol.rva.toString(16)}`, '--scope', 'selected', '--out', out];
    setRunSummary(`Decompile RVA 0x${selectedSymbol.rva.toString(16).toUpperCase()}`);
    setLines([`$ ${displayCommand(executable, args)}`, '']);
    setStatus('running');
    setScreen('running');
    running.current = runCommand(
      executable,
      args,
      workspaceRoot,
      (channel, text) => setLines(current => [...current, ...text.replaceAll('\r\n', '\n').split('\n').filter(Boolean).map(line => channel === 'stderr' ? `! ${line}` : line)].slice(-1000)),
      (code, signal) => {
        running.current = null;
        setExitCode(code);
        setStatus(signal ? 'cancelled' : code === 0 ? 'passed' : 'failed');
        const absolute = resolve(workspaceRoot, out);
        if (code === 0 && existsSync(absolute)) {
          setArtifact({path: absolute, lines: readFileSync(absolute, 'utf8').replaceAll('\r\n', '\n').split('\n')});
          setArtifactOffset(0);
          setViewerReturn('function');
          setScreen('viewer');
        } else {
          setScreen('result');
        }
      },
    );
  };

  const pseudocodePath = (): string | undefined => {
    if (workflow.id === 'decompile') return resolve(workspaceRoot, values.out);
    if (workflow.id !== 'analyze') return undefined;
    const extension = extname(values.binary);
    const stem = basename(values.binary, extension) || 'binary';
    const root = values.out?.trim() || join('windissect-work', stem);
    return resolve(workspaceRoot, root, 'pseudocode.c');
  };

  const openPseudocode = (): void => {
    const path = pseudocodePath();
    if (!path || !existsSync(path)) return;
    setArtifact({path, lines: readFileSync(path, 'utf8').replaceAll('\r\n', '\n').split('\n')});
    setArtifactOffset(0);
    setScreen('viewer');
  };

  useEffect(() => () => running.current?.cancel(), []);

  useInput((input, key) => {
    if ((screen === 'picker' || screen === 'menu') && input === 'q') exit();
    if (screen === 'menu' && input === 'o') setScreen('picker');
    if ((screen === 'form' || screen === 'preview') && key.ctrl && input === 'c') exit();
    if (screen === 'preview') {
      if (key.escape) setScreen('form');
      if (key.return) start();
    }
    if (screen === 'running' && key.ctrl && input === 'c') running.current?.cancel();
    if (screen === 'result') {
      if (input === 'q') exit();
      if (input === 'r') start();
      if (input === 'v') openPseudocode();
      if (input === 'b') {
        const path = analyzedIrPath();
        if (path) openDatabase(path);
      }
      if (key.return) setScreen('menu');
    }
    if (screen === 'browser') {
      if (key.escape) setScreen('menu');
      if (input === 'c') setCandidateOnly(current => !current);
      if (input === 'h') setHideHelpers(current => !current);
    }
    if (screen === 'strings') {
      if (input === 'q') exit();
      if (key.escape) setScreen('menu');
      if (input === 'x') setStringReferenceIndex(current => current + 1);
    }
    if (screen === 'function') {
      if (input === 'q') exit();
      if (key.escape) setScreen(functionReturn);
      if (input === 'd') decompileSelected();
    }
    if (screen === 'viewer') {
      const page = Math.max(5, logHeight - 2);
      if (input === 'q') exit();
      if (key.escape) setScreen(viewerReturn);
      if (key.upArrow) setArtifactOffset(current => Math.max(0, current - 1));
      if (key.downArrow) setArtifactOffset(current => Math.min(Math.max(0, (artifact?.lines.length ?? 1) - page), current + 1));
      if (key.pageUp) setArtifactOffset(current => Math.max(0, current - page));
      if (key.pageDown) setArtifactOffset(current => Math.min(Math.max(0, (artifact?.lines.length ?? 1) - page), current + page));
    }
  });

  const logHeight = Math.max(8, (((stdout as NodeJS.WriteStream | undefined)?.rows) ?? 24) - 12);
  const visibleLines = lines.slice(-logHeight);

  return (
    <Box flexDirection="column">
      <Header binary={executable} status={status} />
      {screen === 'picker' && (
        <TargetPicker
          files={discoveredFiles}
          onSelect={path => {
            setTarget(path);
            setScreen('menu');
          }}
        />
      )}
      {screen === 'menu' && <Menu target={target} onSelect={chooseWorkflow} />}
      {screen === 'form' && (
        <Form
          key={workflow.id}
          workflow={workflow}
          values={values}
          setValues={setValues}
          onComplete={() => {
            if (workflow.id === 'browse') {
              if (values.binary?.trim()) setTarget(resolve(workspaceRoot, values.binary));
              openDatabase(values.ir);
            } else {
              const selectedBinary = values.binary?.trim() || values.dll?.trim();
              if (selectedBinary) setTarget(resolve(workspaceRoot, selectedBinary));
              setScreen('preview');
            }
          }}
          onBack={() => setScreen('menu')}
        />
      )}
      {screen === 'browser' && database && (
        <Box marginTop={1}>
          <Box width="52%" paddingRight={1}>
            <FunctionBrowser
              database={database}
              candidateOnly={candidateOnly}
              hideHelpers={hideHelpers}
              selected={selectedSymbol}
              onHighlight={setSelectedSymbol}
              onSelect={symbol => {
                setSelectedSymbol(symbol);
                setFunctionReturn('browser');
                setScreen('function');
              }}
            />
          </Box>
          <Box width="48%" marginTop={2} borderStyle="round" borderColor="blue">
            <FunctionPreview
              symbol={selectedSymbol}
              analysis={database.functions?.find(item => item.rva === selectedSymbol?.rva)}
            />
          </Box>
        </Box>
      )}
      {screen === 'strings' && (
        <StringExplorer
          matches={stringMatches}
          database={database}
          selected={selectedString}
          referenceIndex={stringReferenceIndex}
          onHighlight={match => {
            setSelectedString(match);
            setStringReferenceIndex(0);
          }}
          onOpen={match => {
            const references = referencesForString(database, match);
            const reference = references.length ? references[stringReferenceIndex % references.length] : undefined;
            const symbol = reference && database?.symbols.find(item => item.rva === reference.func.rva);
            if (symbol) {
              setSelectedString(match);
              setSelectedSymbol(symbol);
              setFunctionReturn('strings');
              setScreen('function');
            }
          }}
        />
      )}
      {screen === 'function' && database && selectedSymbol && (
        <FunctionDetail
          symbol={selectedSymbol}
          analysis={database.functions?.find(item => item.rva === selectedSymbol.rva)}
        />
      )}
      {screen === 'preview' && (
        <Box flexDirection="column" marginTop={1}>
          <Text bold color={workflow.accent}>{invocation.summary}</Text>
          <Box marginTop={1} borderStyle="round" borderColor="yellow" paddingX={1} flexDirection="column">
            <Text bold>Command preview</Text>
            <Text wrap="wrap">{displayCommand(executable, invocation.args)}</Text>
          </Box>
          <Box marginTop={1}><Text color="yellow">Press Enter to run</Text></Box>
        </Box>
      )}
      {(screen === 'running' || screen === 'result') && (
        <Box flexDirection="column" marginTop={1}>
          <Box justifyContent="space-between">
            <Text bold>{runSummary || invocation.summary}</Text>
            <Text color={statusColor(status)}>{status === 'running' ? 'working…' : `exit ${exitCode ?? 'signal'}`}</Text>
          </Box>
          <Box height={logHeight + 2} borderStyle="round" borderColor={statusColor(status)} paddingX={1} flexDirection="column">
            {visibleLines.length
              ? visibleLines.map((line, index) => <Text key={`${index}-${line}`} color={line.startsWith('! ') ? 'red' : undefined}>{line || ' '}</Text>)
              : <Text dimColor>Waiting for output…</Text>}
          </Box>
          {screen === 'result' && (
            <Text color={statusColor(status)} bold>
              {status === 'passed' ? '✓ Completed successfully' : status === 'cancelled' ? '■ Cancelled' : '✗ Command failed'}
              <Newline />
            </Text>
          )}
        </Box>
      )}
      {screen === 'viewer' && artifact && (
        <Box flexDirection="column" marginTop={1}>
          <Box justifyContent="space-between">
            <Text bold color="yellow">CANDIDATE PSEUDOCODE</Text>
            <Text dimColor>{artifact.path}</Text>
          </Box>
          <Box height={logHeight + 2} borderStyle="round" borderColor="yellow" paddingX={1} flexDirection="column">
            {artifact.lines.slice(artifactOffset, artifactOffset + logHeight).map((line, index) => (
              <Text key={`${artifactOffset + index}-${line}`}>{line || ' '}</Text>
            ))}
          </Box>
          <Text dimColor>Reconstructed logic only—not verified original source or ABI truth.</Text>
        </Box>
      )}
      <Footer screen={screen} />
    </Box>
  );
}

if (!process.stdin.isTTY) {
  console.error('windissect-tui requires an interactive terminal (TTY).');
  process.exitCode = 1;
} else {
  render(<App />, {exitOnCtrlC: false});
}
