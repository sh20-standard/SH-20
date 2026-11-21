//! The block file: what the follower kept of each block, so that a restart goes on from where
//! it stopped instead of asking the source for every block since activation.
//!
//! `blocks.jsonl` in the data folder, one JSON object per line, only ever appended to:
//!
//! - first line: `{"sh20-indexer-rs":"blocks","version":1,"activation":A}`;
//! - a block: `{"height":H,"hash":"…","prev":"…","txs":[…]}`, transactions as the vectors
//!   write them (`json::tx_from_vector`);
//! - a rollback: `{"rollback":H}`, the block at `H` and those after it are gone.
//!
//! It holds chain data only, no state: the indexer applies the blocks again when it starts.
//! A line cut short by a crash is dropped when the file is read.

use crate::chain::Block;
use crate::follow::SourceBlock;
use crate::json::{tx_from_vector, tx_to_vector};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "blocks.jsonl";
const VERSION: u64 = 1;

pub struct BlockFile {
    file: File,
}

fn header(activation: u32) -> Value {
    json!({ "sh20-indexer-rs": "blocks", "version": VERSION, "activation": activation })
}

fn block_line(b: &SourceBlock) -> Value {
    json!({
        "height": b.block.height,
        "hash": b.hash,
        "prev": b.prev,
        "txs": b.block.txs.iter().map(tx_to_vector).collect::<Vec<_>>(),
    })
}

fn block_of(v: &Value) -> Result<SourceBlock, String> {
    let text = |key: &str| v.get(key).and_then(Value::as_str).map(str::to_string).ok_or(format!("no \"{key}\""));
    let height = v.get("height").and_then(Value::as_u64).and_then(|h| u32::try_from(h).ok()).ok_or("no \"height\"")?;
    let txs = v.get("txs").and_then(Value::as_array).ok_or("no \"txs\"")?;
    let txs = txs.iter().map(tx_from_vector).collect::<Result<Vec<_>, _>>()?;
    Ok(SourceBlock { hash: text("hash")?, prev: text("prev")?, block: Block { height, txs } })
}

fn write_all(path: &Path, activation: u32, blocks: &[SourceBlock]) -> std::io::Result<()> {
    let tmp = path.with_extension("jsonl.tmp");
    let mut out = std::io::BufWriter::new(File::create(&tmp)?);
    writeln!(out, "{}", header(activation))?;
    for b in blocks {
        writeln!(out, "{}", block_line(b))?;
    }
    out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    std::fs::rename(&tmp, path)
}

impl BlockFile {
    /// Opens the block file of `dir` (creating both when missing) and returns the blocks it
    /// holds, in order. The file must have been written for the same activation height.
    pub fn open(dir: &Path, activation: u32) -> Result<(BlockFile, Vec<SourceBlock>), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let path: PathBuf = dir.join(FILE_NAME);
        let at = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
        let mut blocks: Vec<SourceBlock> = Vec::new();
        let mut tidy = true;
        match std::fs::read_to_string(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => tidy = false,
            Err(e) => return Err(at(&e)),
            Ok(text) => {
                // a line is whole when a newline ends it: the last piece, if any, was cut short
                let mut lines: Vec<&str> = text.split('\n').collect();
                tidy &= lines.pop() == Some("");
                let mut lines = lines.into_iter().enumerate();
                match lines.next() {
                    None => tidy = false,
                    Some((_, first)) => {
                        let h: Value = serde_json::from_str(first).map_err(|e| at(&format!("line 1: {e}")))?;
                        if h.get("sh20-indexer-rs") != Some(&json!("blocks"))
                            || h.get("version") != Some(&json!(VERSION))
                        {
                            return Err(at(&"not a block file of this version"));
                        }
                        if h.get("activation") != Some(&json!(activation)) {
                            return Err(at(&format!(
                                "written for activation height {}, not {activation}: use another folder",
                                h["activation"]
                            )));
                        }
                    }
                }
                for (n, line) in lines {
                    let v: Value = serde_json::from_str(line).map_err(|e| at(&format!("line {}: {e}", n + 1)))?;
                    if let Some(h) = v.get("rollback").and_then(Value::as_u64) {
                        blocks.retain(|b| u64::from(b.block.height) < h);
                        tidy = false;
                    } else {
                        blocks.push(block_of(&v).map_err(|e| at(&format!("line {}: {e}", n + 1)))?);
                    }
                }
            }
        }
        // rewritten without what was rolled back or cut short
        if !tidy {
            write_all(&path, activation, &blocks).map_err(|e| at(&e))?;
        }
        let file = OpenOptions::new().append(true).open(&path).map_err(|e| at(&e))?;
        Ok((BlockFile { file }, blocks))
    }

    fn line(&mut self, v: Value) -> std::io::Result<()> {
        let mut text = v.to_string();
        text.push('\n');
        self.file.write_all(text.as_bytes())?;
        self.file.sync_data()
    }

    pub fn block(&mut self, b: &SourceBlock) -> std::io::Result<()> {
        self.line(block_line(b))
    }

    /// The block at `height` was rolled back.
    pub fn rollback(&mut self, height: u32) -> std::io::Result<()> {
        self.line(json!({ "rollback": height }))
    }
}
