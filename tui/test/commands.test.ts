import assert from 'node:assert/strict';
import test from 'node:test';
import {join} from 'node:path';
import {buildInvocation, displayCommand, missingRequiredFields, workflows} from '../src/commands.js';

test('extract keeps paths as separate process arguments', () => {
  const invocation = buildInvocation('extract', {
    dll: 'C:\\Program Files\\target.dll',
    pdb: 'C:\\Symbols\\target.pdb',
    out: 'work\\target.json',
  });
  assert.deepEqual(invocation.args, [
    'extract',
    'C:\\Program Files\\target.dll',
    '--out',
    'work\\target.json',
    '--pdb',
    'C:\\Symbols\\target.pdb',
  ]);
});

test('analyze builds a one-command workspace invocation', () => {
  assert.deepEqual(buildInvocation('analyze', {
    binary: 'challenge.exe', pdb: '', out: 'work\\challenge',
  }).args, ['analyze', 'challenge.exe', '--out', 'work\\challenge']);
});

test('decompile keeps candidate output explicit', () => {
  assert.deepEqual(buildInvocation('decompile', {
    binary: 'challenge.exe', out: 'pseudo.c', ida: '', scope: 'target',
  }).args, ['decompile', 'challenge.exe', '--out', 'pseudo.c', '--scope', 'target']);
});

test('string search emits a positional query and scan controls', () => {
  assert.deepEqual(buildInvocation('strings', {
    binary: 'challenge.exe', query: 'flag{', min: '5', encoding: 'ascii', limit: '50',
  }).args, [
    'strings', 'challenge.exe', 'flag{', '--min-length', '5', '--encoding', 'ascii', '--limit', '50',
  ]);
});

test('optional values do not emit empty flags', () => {
  assert.deepEqual(buildInvocation('verify', {ir: 'ir.json', profile: ''}).args, [
    'verify', '--ir', 'ir.json',
  ]);
});

test('diff emits both requested report paths', () => {
  assert.deepEqual(buildInvocation('diff', {
    old: 'old.json', new: 'new.json', json: 'diff.json', markdown: 'diff.md',
  }).args, [
    'diff', 'old.json', 'new.json', '--json-out', 'diff.json', '--markdown-out', 'diff.md',
  ]);
});

test('required field validation uses workflow schema', () => {
  const extract = workflows.find(workflow => workflow.id === 'extract')!;
  assert.deepEqual(missingRequiredFields(extract, {dll: '', pdb: '', out: 'out.json'}).map(x => x.key), ['dll']);
});

test('default paths use the host separator', () => {
  for (const workflow of workflows) {
    for (const field of workflow.fields) {
      if (field.initial && process.platform !== 'win32') {
        assert.ok(!field.initial.includes('\\'), `${workflow.id}.${field.key} = ${field.initial}`);
      }
    }
  }
  const verify = workflows.find(workflow => workflow.id === 'verify')!;
  assert.equal(verify.fields[0].initial, join('ir', 'symbols.json'));
});

test('display command quotes only its presentation', () => {
  assert.equal(displayCommand('windissect.exe', ['extract', 'C:\\A B\\x.dll']), 'windissect.exe extract "C:\\A B\\x.dll"');
});
