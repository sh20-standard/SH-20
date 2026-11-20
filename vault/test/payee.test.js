// A payee is an address only on a whole standard template; any other script shows as its hex, and
// the buyer's page will not pay it (a TAKE that pays it would not be relayed).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PAYEE_TYPES, addressToScript, scriptToAddress, scriptType, standardPayee } from '../src/btc.js';
import { buildTake, payeeProblem } from '../src/market.js';
import { fromHex, toHex } from '../src/bytes.js';

const h20 = 'ab'.repeat(20);
const h32 = 'cd'.repeat(32);

/** The template is recognised and shown as an address that maps back to the same script; every near miss is not. */
function standard(type, hex, misses, address) {
  const s = fromHex(hex);
  assert.equal(scriptType(s), type);
  assert.ok(standardPayee(s));
  assert.equal(payeeProblem(s), null);
  const a = scriptToAddress(s);
  if (address) assert.equal(a, address);
  assert.equal(toHex(addressToScript(a)), hex, 'the address shown is this script');
  for (const [why, m] of Object.entries(misses)) {
    const x = fromHex(m);
    assert.notEqual(scriptType(x), type, why);
    assert.equal(scriptToAddress(x), null, `${why}: shown as hex, not as an address`);
    assert.match(payeeProblem(x), /not a standard address/, why);
  }
}

test('the payee types are the five standard templates', () => {
  assert.deepEqual([...PAYEE_TYPES], ['p2pkh', 'p2sh', 'p2wpkh', 'p2wsh', 'p2tr']);
  for (const hex of ['6a0401020304', '', '51', '5220' + h32]) assert.equal(standardPayee(fromHex(hex)), false, hex || 'empty');
});

test('P2PKH: 76 a9 14 <20> 88 ac', () => {
  standard('p2pkh', `76a914${h20}88ac`, {
    'another last opcode': `76a914${h20}88ab`,
    'OP_EQUAL for OP_EQUALVERIFY': `76a914${h20}87ac`,
    'a push of 21 into 20 bytes': `76a915${h20}88ac`.slice(0, 50),
    'one byte longer': `76a914${h20}88acac`,
  });
});

test('P2SH: a9 14 <20> 87', () => {
  standard('p2sh', `a914${h20}87`, {
    'OP_EQUALVERIFY for OP_EQUAL': `a914${h20}88`,
    'a push of 21': `a915${h20}87`.slice(0, 46),
    'one byte longer': `a914${h20}8787`,
  });
});

test('P2WPKH: 00 14 <20>', () => {
  standard('p2wpkh', '0014751e76e8199196d454941c45d1b3a323f1433bd6', {
    'a 21-byte program': `0015${h20}ab`,
    'one byte short': `0014${h20}`.slice(0, 42),
  }, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx');
});

test('P2WSH: 00 20 <32>', () => {
  standard('p2wsh', '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262', {
    'a 31-byte push': `001f${h32}`.slice(0, 66),
    'one byte longer': `0020${h32}00`,
  }, 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7');
});

test('P2TR: 51 20 <32>', () => {
  standard('p2tr', '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433', {
    'witness version 2': `5220${h32}`,
    'a 33-byte program': `5121${h32}00`,
    'one byte short': `5120${h32}`.slice(0, 66),
  }, 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c');
});

test('a 25-byte script that only starts like P2PKH: shown as hex, and the buyer cannot pay it', () => {
  const odd = fromHex(`76a914${h20}88ab`); // 25 bytes, OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CODESEPARATOR
  assert.equal(odd.length, 25);
  assert.equal(scriptType(odd), 'unknown', 'not taken for P2PKH');
  assert.equal(scriptToAddress(odd), null, 'never shown as the address of the hash it holds');
  assert.equal(payeeProblem(odd), `the seller's payee is the script 76a914${h20}88ab, not a standard address (P2PKH, P2SH, P2WPKH, P2WSH or P2TR): the network would not relay a transaction that pays it`);
  // refused before the signature, the wallet or any input is looked at
  assert.throws(() => buildTake({ l: { payScript: odd }, sig: new Uint8Array(65) }), /^Error: not bought: the seller's payee is the script 76a914/);

  // the page: shown as hex with a flag, Buy off with the reason, and sendTake refuses it again
  const page = readFileSync(new URL('../src/ui/market-panel.js', import.meta.url), 'utf8');
  assert.match(page, /const payee = \(script\) => scriptToAddress\(script\) \?\? `script \$\{toHex\(script\)\} \(not a standard address\)`/);
  assert.match(page, /const badPayee = c \? payeeProblem\(c\.l\.payScript\) : null;/);
  assert.match(page, /disabled: [^,]*\|\| !!badPayee, name: 'buy', title: badPayee \?\?/, 'Buy is off and says why');
  assert.match(page, /badPayee \? h\('p', \{ class: 'warn err', id: 'payee-problem' \}, `Cannot buy: \$\{badPayee\}\.`\)/, 'and the page says it');
  const take = page.slice(page.indexOf('async function sendTake('), page.indexOf('async function sendCancel('));
  assert.ok(take.indexOf('payeeProblem(fresh.l.payScript)') > 0 && take.indexOf('payeeProblem(fresh.l.payScript)') < take.indexOf('buildTake('), 'checked again on the fresh listing, before the TAKE is built');
});
