//! What the indexer reads from Bitcoin: blocks, transactions, and the two carriers (SPEC-WIRE §3).

use crate::envelope::{MAGIC, VERSION};
use crate::field::Bytes32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// The spent outpoint; `None` for a coinbase input. The txid is in display (RPC) byte order.
    pub prevout: Option<(Bytes32, u32)>,
    /// The input of a coinbase transaction: its witness is not looked at (§3).
    pub coinbase: bool,
    /// The height of the block that confirmed the output this input spends, when the source
    /// gives it (`prevout.height` of `getblock <hash> 3`). A DEPLOY needs it for input 0 (§5).
    pub prev_height: Option<u32>,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Satoshis.
    pub value: u64,
    pub script: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    /// Display (RPC) byte order.
    pub txid: Bytes32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub height: u32,
    pub txs: Vec<Tx>,
}

pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_1: u8 = 0x51;
pub const OP_16: u8 = 0x60;
pub const OP_IF: u8 = 0x63;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_RETURN: u8 = 0x6a;
pub const MAX_PUSH: usize = 520;

/// One script instruction. A push keeps its data and whether its encoding is the minimal one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instr {
    Push { data: Vec<u8>, minimal: bool },
    Op(u8),
}

/// A minimal push, as §3 defines it: `OP_0` for no data, `OP_1`…`OP_16` and `OP_1NEGATE` for
/// the single bytes they push, then by length the opcode `n`, `OP_PUSHDATA1`, `OP_PUSHDATA2`,
/// and `OP_PUSHDATA4` above 65,535 bytes.
fn is_minimal(opcode: u8, data: &[u8]) -> bool {
    match data.len() {
        0 => opcode == OP_0,
        1 if (1..=16).contains(&data[0]) => opcode == OP_1 + data[0] - 1,
        1 if data[0] == 0x81 => opcode == OP_1NEGATE,
        n if n <= 75 => opcode as usize == n,
        n if n <= 255 => opcode == OP_PUSHDATA1,
        n if n <= 65535 => opcode == OP_PUSHDATA2,
        _ => opcode == OP_PUSHDATA4,
    }
}

/// Splits a script into instructions. `None` when a push runs past the end of the script.
pub fn parse_script(script: &[u8]) -> Option<Vec<Instr>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            OP_0 => {
                out.push(Instr::Push { data: Vec::new(), minimal: true });
                continue;
            }
            0x01..=0x4b => op as usize,
            OP_PUSHDATA1 => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            OP_PUSHDATA2 => {
                let b = script.get(i..i + 2)?;
                i += 2;
                u16::from_le_bytes([b[0], b[1]]) as usize
            }
            OP_PUSHDATA4 => {
                let b = script.get(i..i + 4)?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            OP_1NEGATE => {
                out.push(Instr::Push { data: vec![0x81], minimal: true });
                continue;
            }
            OP_1..=OP_16 => {
                out.push(Instr::Push { data: vec![op - OP_1 + 1], minimal: true });
                continue;
            }
            _ => {
                out.push(Instr::Op(op));
                continue;
            }
        };
        let data = script.get(i..i.checked_add(len)?)?;
        i += len;
        out.push(Instr::Push { data: data.to_vec(), minimal: is_minimal(op, data) });
    }
    Some(out)
}

/// The OP_RETURN carrier: `OP_RETURN <push>`, exactly one minimal push, data starting with `SH20`.
pub fn op_return_envelope(script: &[u8]) -> Option<Vec<u8>> {
    if script.first() != Some(&OP_RETURN) {
        return None;
    }
    let ins = parse_script(&script[1..])?;
    match ins.as_slice() {
        [Instr::Push { data, minimal: true }] if data.starts_with(MAGIC) => Some(data.clone()),
        _ => None,
    }
}

/// The tapscript of a script-path spend, read from the witness stack alone: annex dropped,
/// then the control block (leaf version `0xc0`) is last and the script comes just before it.
pub fn tapscript(witness: &[Vec<u8>]) -> Option<&[u8]> {
    let mut stack = witness;
    if stack.len() >= 2 && stack[stack.len() - 1].first() == Some(&0x50) {
        stack = &stack[..stack.len() - 1]; // annex
    }
    if stack.len() < 2 {
        return None;
    }
    let control = &stack[stack.len() - 1];
    let well_formed = control.len() >= 33
        && (control.len() - 33).is_multiple_of(32)
        && control.len() <= 33 + 32 * 128
        && control[0] & 0xfe == 0xc0;
    if !well_formed {
        return None;
    }
    Some(&stack[stack.len() - 2])
}

/// Every `OP_0 OP_IF <push "SH20"> <push>... OP_ENDIF` in a tapscript, as `"SH20" ‖ concat(pushes)`.
pub fn witness_envelopes(script: &[u8]) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    let Some(ins) = parse_script(script) else {
        return found;
    };
    let is_magic = |i: &Instr| matches!(i, Instr::Push { data, minimal: true } if data.as_slice() == MAGIC);
    let is_op0 = |i: &Instr| matches!(i, Instr::Push { data, minimal: true } if data.is_empty());
    let mut i = 0;
    while i + 2 < ins.len() {
        if !(is_op0(&ins[i]) && ins[i + 1] == Instr::Op(OP_IF) && is_magic(&ins[i + 2])) {
            i += 1;
            continue;
        }
        let mut env = MAGIC.to_vec();
        let mut j = i + 3;
        let mut closed = false;
        while j < ins.len() {
            match &ins[j] {
                Instr::Push { data, minimal: true } if data.len() <= MAX_PUSH => env.extend_from_slice(data),
                Instr::Op(OP_ENDIF) => {
                    closed = true;
                    break;
                }
                _ => break,
            }
            j += 1;
        }
        if closed {
            found.push(env);
            i = j + 1;
        } else {
            i += 1;
        }
    }
    found
}

/// Where an envelope was found. A DEPLOY is accepted in a witness only (§5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    OpReturn,
    Witness,
}

/// An envelope and the carrier that held it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    pub carrier: Carrier,
    pub bytes: Vec<u8>,
}

/// Every envelope candidate a transaction carries: the OP_RETURN outputs in output order,
/// then the tapscript of input 0. Each starts with `SH20`; nothing else is checked here.
/// A coinbase is read for its OP_RETURN outputs only: the witness of its input is not looked at.
pub fn carried(tx: &Tx) -> Vec<Carried> {
    let mut found: Vec<Carried> = tx
        .vout
        .iter()
        .filter_map(|o| op_return_envelope(&o.script))
        .map(|bytes| Carried { carrier: Carrier::OpReturn, bytes })
        .collect();
    if let Some(script) = tx.vin.first().filter(|i| !i.coinbase).and_then(|i| tapscript(&i.witness)) {
        found.extend(witness_envelopes(script).into_iter().map(|bytes| Carried { carrier: Carrier::Witness, bytes }));
    }
    found
}

/// The envelopes of a transaction that count (§3): every envelope found, except one whose
/// fifth byte (the version) exists and is not `0x00`. One is applied; two or more refuse the
/// transaction.
pub fn counted(tx: &Tx) -> Vec<Carried> {
    carried(tx).into_iter().filter(|c| c.bytes.len() < 5 || c.bytes[4] == VERSION).collect()
}

/// The bytes of `carried`.
pub fn envelopes(tx: &Tx) -> Vec<Vec<u8>> {
    carried(tx).into_iter().map(|c| c.bytes).collect()
}

/// The bytes of `counted`.
pub fn counted_envelopes(tx: &Tx) -> Vec<Vec<u8>> {
    counted(tx).into_iter().map(|c| c.bytes).collect()
}

/// True when the script is exactly `OP_1 <key>`: P2TR to that output key.
pub fn is_p2tr_to(script: &[u8], key: &Bytes32) -> bool {
    script.len() == 34 && script[0] == OP_1 && script[1] == 0x20 && script[2..] == key[..]
}

/// Sats carried by OP_RETURN outputs (payMode 1).
pub fn burned_sats(tx: &Tx) -> u128 {
    tx.vout.iter().filter(|o| o.script.first() == Some(&OP_RETURN)).map(|o| o.value as u128).sum()
}

/// Sats paid to outputs whose script is exactly `script` (payMode 2, listings).
pub fn paid_to(tx: &Tx, script: &[u8]) -> u128 {
    tx.vout.iter().filter(|o| o.script == script).map(|o| o.value as u128).sum()
}
