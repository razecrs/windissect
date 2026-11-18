import assert from 'node:assert/strict';
import test from 'node:test';
import {helperReason} from '../src/triage.js';

test('marks explicit Windissect library facts as helpers', () => {
  assert.equal(helperReason({id: 'anything', library: true}), 'Windissect library/runtime classification');
});

test('marks compiler thunks and CRT names without hiding normal code', () => {
  assert.equal(helperReason({id: 'sub_1000', kind: 'thunk'}), 'trivial thunk or forwarding stub');
  assert.match(helperReason({id: '__security_check_cookie'}) ?? '', /compiler/u);
  assert.equal(helperReason({id: 'HandleChallengeRequest', kind: 'c-func'}), undefined);
});

test('recognizes standard-library and delay-import implementation details', () => {
  assert.match(helperReason({id: 'std::vector<int>::reserve'}) ?? '', /standard-library/u);
  assert.match(helperReason({id: '__imp_load_GetDpiForSystem'}) ?? '', /delay-import/u);
});
