//! Blocks from JSON: `bitcoin-cli getblock <hash> 2`, and the scenario of the vectors.

use crate::chain::{Block, Tx, TxIn, TxOut};
use crate::field::{unhex, unhex32};
use serde_json::Value;

type Res<T> = Result<T, String>;

fn str_of<'a>(v: &'a Value, key: &str) -> Res<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or_else(|| format!("missing string \"{key}\""))
}

fn array_of<'a>(v: &'a Value, key: &str) -> Res<&'a Vec<Value>> {
    v.get(key).and_then(Value::as_array).ok_or_else(|| format!("missing array \"{key}\""))
}

fn u32_of(v: &Value, key: &str) -> Res<u32> {
    v.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("missing number \"{key}\""))
}

fn hex_of(s: &str) -> Res<Vec<u8>> {
    unhex(s).ok_or_else(|| format!("bad hex \"{s}\""))
}

fn txid_of(s: &str) -> Res<[u8; 32]> {
    unhex32(s).ok_or_else(|| format!("bad txid \"{s}\""))
}

fn witness_of(items: Option<&Value>) -> Res<Vec<Vec<u8>>> {
    match items.and_then(Value::as_array) {
        None => Ok(Vec::new()),
        Some(a) => a.iter().map(|w| hex_of(w.as_str().ok_or("witness item is not a string")?)).collect(),
    }
}

/// A BTC amount as Bitcoin Core prints it (`0.00000330`), in satoshis, without floating point.
pub fn btc_to_sats(text: &str) -> Res<u64> {
    let bad = || format!("bad BTC amount \"{text}\"");
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    if !digits(whole) || (!frac.is_empty() && !digits(frac)) || frac.len() > 8 {
        return Err(bad());
    }
    let whole: u64 = whole.parse().map_err(|_| bad())?;
    let frac: u64 = format!("{frac:0<8}").parse().map_err(|_| bad())?;
    whole.checked_mul(100_000_000).and_then(|w| w.checked_add(frac)).ok_or_else(bad)
}

/// One `getblock <hash> 3` answer (bare, or wrapped in a JSON-RPC `{"result": …}`). Verbosity 2
/// reads too, without the height of the spent outputs: enough until a DEPLOY is revealed.
pub fn block_from_getblock(text: &str) -> Res<Block> {
    let root: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let b = match root.get("result") {
        Some(r) if r.is_object() => r,
        _ => &root,
    };
    let height = u32_of(b, "height")?;
    let mut txs = Vec::new();
    for t in array_of(b, "tx")? {
        if !t.is_object() {
            return Err("transactions are not decoded: use `getblock <hash> 2`".into());
        }
        let txid = txid_of(str_of(t, "txid")?)?;
        let mut vin = Vec::new();
        for i in array_of(t, "vin")? {
            let coinbase = i.get("coinbase").is_some();
            let prevout = if coinbase { None } else { Some((txid_of(str_of(i, "txid")?)?, u32_of(i, "vout")?)) };
            // `getblock <hash> 3` gives the spent output, and the height of its block
            let prev_height = i
                .get("prevout")
                .and_then(|p| p.get("height"))
                .and_then(Value::as_u64)
                .and_then(|h| u32::try_from(h).ok());
            vin.push(TxIn { prevout, coinbase, prev_height, witness: witness_of(i.get("txinwitness"))? });
        }
        let mut vout = Vec::new();
        for o in array_of(t, "vout")? {
            // serde_json keeps the number's text (feature `arbitrary_precision`)
            let value = o.get("value").filter(|v| v.is_number()).ok_or("missing number \"value\"")?.to_string();
            let script = o.get("scriptPubKey").ok_or("missing \"scriptPubKey\"")?;
            vout.push(TxOut { value: btc_to_sats(&value)?, script: hex_of(str_of(script, "hex")?)? });
        }
        txs.push(Tx { txid, vin, vout });
    }
    Ok(Block { height, txs })
}

/// A block of the scenario in `indexer/vectors/v0.3.json`
/// (`value` in satoshis as a string, `script` and `witness` in hex).
pub fn block_from_vector(b: &Value) -> Res<Block> {
    let height = u32_of(b, "height")?;
    let mut txs = Vec::new();
    for t in array_of(b, "txs")? {
        str_of(t, "txid")?;
        txs.push(tx_from_vector(t)?);
    }
    Ok(Block { height, txs })
}

/// A transaction as the vectors write it, in the scenario or in a carrier case. A carrier case
/// has no txid (32 zero bytes here) and its inputs give their witness only: they spend
/// nothing. `{"coinbase": true}` is the input of a coinbase. `prevHeight` is the height of the
/// block that confirmed the output an input spends, given where a DEPLOY needs it.
pub fn tx_from_vector(t: &Value) -> Res<Tx> {
    let txid = match t.get("txid") {
        Some(_) => txid_of(str_of(t, "txid")?)?,
        None => [0u8; 32],
    };
    let mut vin = Vec::new();
    for i in array_of(t, "vin")? {
        let coinbase = i.get("coinbase").is_some_and(|c| c.as_bool() != Some(false));
        let prevout = match i.get("txid") {
            Some(_) if !coinbase => Some((txid_of(str_of(i, "txid")?)?, u32_of(i, "vout")?)),
            _ => None,
        };
        let prev_height = match i.get("prevHeight") {
            Some(_) => Some(u32_of(i, "prevHeight")?),
            None => None,
        };
        vin.push(TxIn { prevout, coinbase, prev_height, witness: witness_of(i.get("witness"))? });
    }
    let mut vout = Vec::new();
    for o in array_of(t, "vout")? {
        let value = str_of(o, "value")?.parse::<u64>().map_err(|e| e.to_string())?;
        vout.push(TxOut { value, script: hex_of(str_of(o, "script")?)? });
    }
    Ok(Tx { txid, vin, vout })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(btc_to_sats("0.00000330"), Ok(330));
        assert_eq!(btc_to_sats("0"), Ok(0));
        assert_eq!(btc_to_sats("1"), Ok(100_000_000));
        assert_eq!(btc_to_sats("20999999.97690000"), Ok(2_099_999_997_690_000));
        assert_eq!(btc_to_sats("0.1"), Ok(10_000_000));
        assert!(btc_to_sats("1e-8").is_err());
        assert!(btc_to_sats("0.000000001").is_err());
        assert!(btc_to_sats("-1").is_err());
    }

    #[test]
    fn getblock() {
        let text = r#"{"hash":"00","height":7,"tx":[
          {"txid":"1111111111111111111111111111111111111111111111111111111111111111",
           "vin":[{"coinbase":"0101","txinwitness":["00"],"sequence":1}],
           "vout":[{"value":50.00000000,"n":0,"scriptPubKey":{"hex":"51"}}]},
          {"txid":"2222222222222222222222222222222222222222222222222222222222222222",
           "vin":[{"txid":"1111111111111111111111111111111111111111111111111111111111111111","vout":3,"txinwitness":["aa","bb"],
                   "prevout":{"generated":false,"height":5,"value":0.00001000,"scriptPubKey":{"hex":"51"}}}],
           "vout":[{"value":0.00000330,"n":0,"scriptPubKey":{"hex":"6a0453483230"}}]}]}"#;
        let b = block_from_getblock(text).unwrap();
        assert_eq!(b.height, 7);
        assert_eq!(b.txs.len(), 2);
        assert_eq!(b.txs[0].vin[0].prevout, None);
        assert!(b.txs[0].vin[0].coinbase && !b.txs[1].vin[0].coinbase);
        assert_eq!((b.txs[0].vin[0].prev_height, b.txs[1].vin[0].prev_height), (None, Some(5)));
        assert_eq!(b.txs[0].vout[0].value, 5_000_000_000);
        assert_eq!(b.txs[1].vin[0].prevout, Some(([0x11; 32], 3)));
        assert_eq!(b.txs[1].vin[0].witness, vec![vec![0xaa], vec![0xbb]]);
        assert_eq!(b.txs[1].vout[0].value, 330);
        assert!(block_from_getblock(r#"{"height":1,"tx":["abcd"]}"#).is_err());
    }
}
