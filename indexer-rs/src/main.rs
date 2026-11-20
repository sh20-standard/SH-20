//! `sh20-indexer-rs replay <folder of getblock JSON files>`: the digest of every block.

use sh20_indexer::field::{fr_to_be, hex};
use sh20_indexer::json::block_from_getblock;
use sh20_indexer::{Block, Indexer, Profile, RejectAll, SpendVerifier, TestVerifier};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
usage: sh20-indexer-rs replay <folder> [options]

  <folder>   JSON files, one block each, as printed by `bitcoin-cli getblock <hash> 3`.
             Files are ordered by the height they contain; heights must be consecutive.
             Verbosity 2 reads too, but a DEPLOY needs the height of the output its input 0
             spends (prevout.height, verbosity 3 only): without it the replay stops there.

options:
  --activation <height>   activation height A (default: the lowest height in the folder)
  --deploy-burn <D>       SH20 burned by every DEPLOY (default: 0)
  --window <W>            anchor window (default: 100)
  --min-depth <K_min>     anchor minimum depth (default: 1)
  --maturity <N>          blocks a DEPLOY commit must have behind it (default: 6)
  --verifier <name>       reject (default: every spend is refused) or
                          test (accepts the proof \"valid-proof\" padded with zeros to 480 bytes)
  --json                  one JSON object per block: height, root, events, eventsH, digest, rejected

Prints one line per block from the activation block on: `<height> <digest>`.
Blocks below the activation height are not read.";

struct Options {
    folder: String,
    activation: Option<u32>,
    deploy_burn: u64,
    window: u32,
    min_depth: u32,
    maturity: u32,
    verifier: String,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    if args.first().map(String::as_str) != Some("replay") {
        return Err("expected the command `replay`".into());
    }
    let mut o = Options {
        folder: String::new(),
        activation: None,
        deploy_burn: 0,
        window: 100,
        min_depth: 1,
        maturity: sh20_indexer::state::DEPLOY_MATURITY,
        verifier: "reject".into(),
        json: false,
    };
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        let number = |name: &str, v: String| v.parse::<u64>().map_err(|_| format!("{name}: \"{v}\" is not a number"));
        let small = |name: &str, v: String| v.parse::<u32>().map_err(|_| format!("{name}: \"{v}\" is not a height"));
        match a.as_str() {
            "--activation" => o.activation = Some(small(a, value(a)?)?),
            "--deploy-burn" => o.deploy_burn = number(a, value(a)?)?,
            "--window" => o.window = small(a, value(a)?)?,
            "--min-depth" => o.min_depth = small(a, value(a)?)?,
            "--maturity" => o.maturity = small(a, value(a)?)?,
            "--verifier" => o.verifier = value(a)?,
            "--json" => o.json = true,
            _ if a.starts_with("--") => return Err(format!("unknown option {a}")),
            _ if o.folder.is_empty() => o.folder = a.clone(),
            _ => return Err(format!("unexpected argument {a}")),
        }
    }
    if o.folder.is_empty() {
        return Err("no folder given".into());
    }
    Ok(o)
}

fn load_blocks(folder: &Path) -> Result<Vec<Block>, String> {
    let mut blocks = Vec::new();
    let entries = std::fs::read_dir(folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        blocks.push(block_from_getblock(&text).map_err(|e| format!("{}: {e}", path.display()))?);
    }
    blocks.sort_by_key(|b| b.height);
    Ok(blocks)
}

fn json_string(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

fn run(o: &Options) -> Result<(), String> {
    let blocks = load_blocks(Path::new(&o.folder))?;
    let first = blocks.first().ok_or("no .json file in the folder")?.height;
    let activation = o.activation.unwrap_or(first);
    if first > activation {
        return Err(format!("the folder starts at block {first}, after the activation block {activation}"));
    }
    let verifier: Box<dyn SpendVerifier> = match o.verifier.as_str() {
        "reject" => Box::new(RejectAll),
        "test" => Box::new(TestVerifier),
        other => return Err(format!("unknown verifier \"{other}\" (reject or test)")),
    };
    let profile = Profile {
        activation_height: activation,
        deploy_burn: o.deploy_burn,
        anchor_window: o.window,
        anchor_min_depth: o.min_depth,
        deploy_maturity: o.maturity,
    };
    eprintln!(
        "profile: A = {activation}, D = {}, W = {}, K_min = {}, N = {}, verifier = {}",
        o.deploy_burn, o.window, o.min_depth, o.maturity, o.verifier
    );

    let mut indexer = Indexer::new(profile, verifier);
    for block in blocks.iter().filter(|b| b.height >= activation) {
        let r = indexer.apply_block(block).map_err(|e| e.to_string())?;
        if o.json {
            let events: Vec<String> = r.events.iter().map(|e| json_string(e.name())).collect();
            let rejected: Vec<String> = r
                .rejected
                .iter()
                .map(|x| {
                    // in a batch, which envelope of the transaction was refused
                    let envelope = x.envelope.map(|i| format!("\"envelope\":{i},")).unwrap_or_default();
                    format!("{{\"txid\":\"{}\",{}\"reason\":{}}}", hex(&x.txid), envelope, json_string(x.reason))
                })
                .collect();
            println!(
                "{{\"height\":{},\"root\":\"{}\",\"events\":[{}],\"eventsH\":\"{}\",\"digest\":\"{}\",\"rejected\":[{}]}}",
                r.height,
                hex(&fr_to_be(&r.root)),
                events.join(","),
                hex(&r.events_bytes),
                hex(&r.digest),
                rejected.join(",")
            );
        } else {
            println!("{} {}", r.height, hex(&r.digest));
        }
    }
    if indexer.tip().is_none() {
        return Err(format!("no block at or after the activation block {activation}"));
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match parse_args(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    match run(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
