// Bitcoin wallet extensions, talked to directly through what they inject in the
// page (no SDK). Each adapter exposes:
//   detect()                         → boolean
//   connect()                        → { address, publicKey, network } of the payment address
//   signPsbt(psbtBytes, indexes, address) → signed PSBT bytes (finalized or not)
//   utxos?(address)                  → spendable UTXOs, when the wallet can list them
// The vault builds every PSBT itself; the wallet only signs the inputs it is asked to.
// None of the three is asked to finalize or broadcast: Xverse and Leather return
// partial signatures, UniSat finalizes; btc.finalizePsbt handles both, and the
// vault broadcasts through Esplora.

import { toHex, fromHex, toBase64, fromBase64 } from './bytes.js';

const NET = 'signet';

/**
 * JSON-RPC providers: Xverse resolves to { result } or { error }; Leather
 * resolves to { result } and rejects with { error }. Both become a value or an Error.
 */
async function rpc(provider, method, params) {
  let res;
  try {
    res = await provider.request(method, params);
  } catch (e) {
    res = e;
  }
  const err = res?.error ?? (res instanceof Error ? res : null);
  if (err) throw new Error(err.message || JSON.stringify(err));
  return res && typeof res === 'object' && 'result' in res ? res.result : res;
}

const xverseProvider = () => globalThis.XverseProviders?.BitcoinProvider ?? globalThis.BitcoinProvider ?? null;

export const WALLETS = [
  {
    id: 'xverse',
    name: 'Xverse',
    detect: () => !!xverseProvider(),
    async connect() {
      const p = xverseProvider();
      const message = 'SH-20 vault: pay for mints on signet';
      // wallet_connect is the current method; getAccounts is the older one
      const res = await rpc(p, 'wallet_connect', { addresses: ['payment'], message, network: 'Signet' })
        .catch(() => rpc(p, 'getAccounts', { purposes: ['payment'], message }));
      let name = (await rpc(p, 'wallet_getNetwork', null).catch(() => null))?.bitcoin?.name ?? res?.network?.bitcoin?.name;
      if (name && name !== 'Signet') {
        await rpc(p, 'wallet_changeNetwork', { name: 'Signet' });
        name = 'Signet';
      }
      const accounts = Array.isArray(res) ? res : res?.addresses ?? [];
      // the payment address is P2WPKH or P2SH-P2WPKH depending on the user's setting; never the ordinals one
      const pay = accounts.find((a) => a.purpose === 'payment');
      if (!pay) throw new Error('Xverse returned no payment address');
      return { address: pay.address, publicKey: pay.publicKey, network: name ?? NET };
    },
    async signPsbt(psbt, indexes, address) {
      const res = await rpc(xverseProvider(), 'signPsbt', { psbt: toBase64(psbt), signInputs: { [address]: indexes }, broadcast: false });
      return fromBase64(res.psbt);
    },
  },
  {
    id: 'unisat',
    name: 'UniSat',
    detect: () => !!globalThis.unisat,
    async connect() {
      const u = globalThis.unisat;
      const [address] = await u.requestAccounts();
      if (u.getChain) {
        const chain = await u.getChain();
        if (chain?.enum !== 'BITCOIN_SIGNET') await u.switchChain('BITCOIN_SIGNET');
      } else if ((await u.getNetwork()) !== 'testnet') {
        throw new Error('this UniSat version cannot switch to signet');
      }
      const [addr] = await u.getAccounts();
      return { address: addr ?? address, publicKey: await u.getPublicKey(), network: NET };
    },
    async signPsbt(psbt, indexes, address) {
      const hex = await globalThis.unisat.signPsbt(toHex(psbt), {
        autoFinalized: true,
        toSignInputs: indexes.map((index) => ({ index, address })),
      });
      return fromHex(hex);
    },
    // UniSat can list the UTXOs that carry no inscription or rune, so a mint
    // never spends a collectible by accident.
    // (not in UniSat's public API docs: used only if present and well formed, else Esplora).
    async utxos() {
      const u = globalThis.unisat;
      if (typeof u.getBitcoinUtxos !== 'function') return null;
      const list = await u.getBitcoinUtxos(0, 100).catch(() => null);
      if (!Array.isArray(list) || !list.every((x) => /^[0-9a-f]{64}$/.test(x?.txid) && Number.isInteger(x.vout) && Number.isInteger(x.satoshis))) return null;
      return list.map((x) => ({ txid: x.txid, vout: x.vout, value: BigInt(x.satoshis), confirmed: true }));
    },
  },
  {
    id: 'leather',
    name: 'Leather',
    detect: () => !!globalThis.LeatherProvider,
    async connect() {
      const res = await rpc(globalThis.LeatherProvider, 'getAddresses', { network: NET });
      // pay from the native segwit address; the taproot one is for collectibles
      const pay = (res.addresses ?? []).find((a) => a.symbol === 'BTC' && a.type === 'p2wpkh');
      if (!pay) throw new Error('Leather returned no native segwit Bitcoin address');
      return { address: pay.address, publicKey: pay.publicKey, network: NET };
    },
    async signPsbt(psbt, indexes) {
      const res = await rpc(globalThis.LeatherProvider, 'signPsbt', { hex: toHex(psbt), network: NET, signAtIndex: indexes, broadcast: false });
      return fromHex(res.hex);
    },
  },
];
