//! `sh20-indexer-rs replay <folder of getblock JSON files>`: the digest of every block.
//! `sh20-indexer-rs follow --rpc <url> | --esplora <url>`: follows a chain and serves the
//! read-only API of `docs/API.md`.

use sh20_indexer::api::Store;
use sh20_indexer::blocks::BlockFile;
use sh20_indexer::field::{fr_to_be, hex};
use sh20_indexer::follow::{Follower, Source, Step};
use sh20_indexer::json::block_from_getblock;
use sh20_indexer::sources::{basic_auth, CoreRpc, Esplora};
use sh20_indexer::{Block, Indexer, PlonkVerifier, Profile, RejectAll, SpendVerifier, TestVerifier};
use std::net::TcpListener;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};
use std::time::Duration;

const USAGE: &str = "\
usage: sh20-indexer-rs replay <folder> [options]
       sh20-indexer-rs follow (--rpc <url> | --esplora <url>) --activation <height> [options]

replay

  <folder>   JSON files, one block each, as printed by `bitcoin-cli getblock <hash> 3`.
             Files are ordered by the height they contain; heights must be consecutive.
             Verbosity 2 reads too, but a DEPLOY needs the height of the output its input 0
             spends (prevout.height, verbosity 3 only): without it the replay stops there.

options:
  --activation <height>   activation height A (default: the lowest height in the folder)
  --deploy-burn <D>       SH20 burned by every DEPLOY (required)
  --window <W>            anchor window (default: 100)
  --min-depth <K_min>     anchor minimum depth (default: 1)
  --maturity <N>          blocks a DEPLOY commit must have behind it (default: 6)
  --verifier <name>       plonk-bn254-hermez (the PLONK verifier of circuit/, under the pinned key),
                          reject-all (default: every spend is refused; `reject` is the same) or
                          test (accepts the proof \"valid-proof\" padded with zeros to 480 bytes)
  --json                  one JSON object per block: height, root, events, eventsH, digest, rejected

Prints one line per block from the activation block on: `<height> <digest>`.
Blocks below the activation height are not read.

A number is decimal digits and nothing else (no sign, no space, no exponent); an option given
twice is refused, in both commands.

follow

  Follows the best chain from the activation block, undoes the blocks a reorg removes (288
  blocks of undo; a deeper reorg stops it), and serves the read-only API of docs/API.md.
  A source that fails is asked again, for as long as it takes.

  --rpc <url>             Bitcoin Core's RPC, e.g. http://127.0.0.1:38332 (needs `getblock <hash> 3`)
  --rpcuser <user>        with --rpcpass <password>, or
  --rpccookie <file>      the node's .cookie file
  --esplora <url>         an Esplora API instead, e.g. https://mempool.space/signet/api
  --activation <height>   activation height A (required)
  --deploy-burn <D>       SH20 burned by every DEPLOY (required)
  --window <W>, --min-depth <K_min>, --maturity <N>, --verifier <name>
                          the rest of the profile, as for replay; every indexer of a network
                          takes the same
  --listen <address>      where the API listens (default: 127.0.0.1:8621)
  --data <folder>         keeps the blocks read in <folder>/blocks.jsonl: a restart goes on from
                          there instead of reading the chain again from the activation block
  --poll <seconds>        how often to ask for a new block at the tip (default: 10)
  --network <name>        the name /status gives (default: what the node says, or \"unknown\")";

#[derive(Default)]
struct Options {
    follow: bool,
    folder: String,
    activation: Option<u32>,
    deploy_burn: Option<u64>,
    window: u32,
    min_depth: u32,
    maturity: u32,
    verifier: String,
    json: bool,
    rpc: Option<String>,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    rpc_cookie: Option<String>,
    esplora: Option<String>,
    listen: String,
    data: Option<String>,
    poll: u64,
    network: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let follow = match args.first().map(String::as_str) {
        Some("replay") => false,
        Some("follow") => true,
        _ => return Err("expected the command `replay` or `follow`".into()),
    };
    let mut o = Options {
        follow,
        window: 100,
        min_depth: 1,
        maturity: sh20_indexer::state::DEPLOY_MATURITY,
        verifier: "reject-all".into(),
        listen: "127.0.0.1:8621".into(),
        poll: 10,
        ..Options::default()
    };
    let mut it = args[1..].iter();
    let mut given: Vec<&str> = Vec::new();
    while let Some(a) = it.next() {
        // an option given twice is refused: which of the two values was meant is not ours to guess
        if a.starts_with("--") {
            if given.contains(&a.as_str()) {
                return Err(format!("{a} is given twice"));
            }
            given.push(a);
        }
        let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        let number = |name: &str, v: String| {
            decimal::<u64>(&v).ok_or(format!("{name}: \"{v}\" is not a number (decimal digits, at most {})", u64::MAX))
        };
        let small = |name: &str, v: String| {
            decimal::<u32>(&v).ok_or(format!("{name}: \"{v}\" is not a number (decimal digits, at most {})", u32::MAX))
        };
        match a.as_str() {
            "--activation" => o.activation = Some(small(a, value(a)?)?),
            "--deploy-burn" => o.deploy_burn = Some(number(a, value(a)?)?),
            "--window" => o.window = small(a, value(a)?)?,
            "--min-depth" => o.min_depth = small(a, value(a)?)?,
            "--maturity" => o.maturity = small(a, value(a)?)?,
            "--verifier" => o.verifier = value(a)?,
            "--json" if !follow => o.json = true,
            "--rpc" if follow => o.rpc = Some(value(a)?),
            "--rpcuser" if follow => o.rpc_user = Some(value(a)?),
            "--rpcpass" if follow => o.rpc_pass = Some(value(a)?),
            "--rpccookie" if follow => o.rpc_cookie = Some(value(a)?),
            "--esplora" if follow => o.esplora = Some(value(a)?),
            "--listen" if follow => o.listen = value(a)?,
            "--data" if follow => o.data = Some(value(a)?),
            "--poll" if follow => o.poll = number(a, value(a)?)?.max(1),
            "--network" if follow => o.network = Some(value(a)?),
            _ if a.starts_with("--") => return Err(format!("unknown option {a}")),
            _ if !follow && o.folder.is_empty() => o.folder = a.clone(),
            _ => return Err(format!("unexpected argument {a}")),
        }
    }
    if follow {
        if o.rpc.is_some() == o.esplora.is_some() {
            return Err("give one source: --rpc <url> or --esplora <url>".into());
        }
        // the spec gives A and D no default, and an indexer with another D is on another chain
        if o.activation.is_none() || o.deploy_burn.is_none() {
            return Err("follow needs --activation <height> and --deploy-burn <D>".into());
        }
        if o.rpc_user.is_some() != o.rpc_pass.is_some() {
            return Err("--rpcuser and --rpcpass go together".into());
        }
        if o.rpc_cookie.is_some() && o.rpc_user.is_some() {
            return Err("--rpccookie or --rpcuser and --rpcpass, not both".into());
        }
        if o.esplora.is_some() && (o.rpc_user.is_some() || o.rpc_cookie.is_some()) {
            return Err("--rpcuser, --rpcpass and --rpccookie go with --rpc".into());
        }
    } else {
        if o.folder.is_empty() {
            return Err("no folder given".into());
        }
        // as for follow: the spec gives D no default, and a replay under another D gives other digests
        if o.deploy_burn.is_none() {
            return Err("replay needs --deploy-burn <D>".into());
        }
    }
    Ok(o)
}

/// A number of the command line: decimal digits and nothing else, in the range of `T`. Rust's own
/// parse takes a leading `+`; the reference's tools do not, and both must take the same lines.
fn decimal<T: std::str::FromStr>(v: &str) -> Option<T> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

/// The verifier, and its name as `/status` gives it (`docs/API.md`).
fn verifier_of(name: &str) -> Result<(Box<dyn SpendVerifier>, &'static str), String> {
    match name {
        "reject-all" | "reject" => Ok((Box::new(RejectAll), "reject-all")),
        "test" => Ok((Box::new(TestVerifier), "test")),
        PlonkVerifier::NAME => Ok((Box::new(PlonkVerifier::pinned()?), PlonkVerifier::NAME)),
        other => Err(format!("unknown verifier \"{other}\" ({}, reject-all or test)", PlonkVerifier::NAME)),
    }
}

fn profile_line(p: &Profile, verifier: &str) -> String {
    format!(
        "profile: A = {}, D = {}, W = {}, K_min = {}, N = {}, verifier = {verifier}",
        p.activation_height, p.deploy_burn, p.anchor_window, p.anchor_min_depth, p.deploy_maturity
    )
}

/// An error is fatal when it is the user's to fix: it ends the command.
fn follow(o: &Options) -> Result<(), String> {
    let profile = Profile {
        activation_height: o.activation.expect("checked by parse_args"),
        deploy_burn: o.deploy_burn.expect("checked by parse_args"),
        anchor_window: o.window,
        anchor_min_depth: o.min_depth,
        deploy_maturity: o.maturity,
    };
    let (verifier, verifier_name) = verifier_of(&o.verifier)?;
    let indexer = Indexer::new(profile, verifier);
    let network = o.network.clone().unwrap_or_else(|| "unknown".into());
    let store = Arc::new(RwLock::new(Store::new(profile, &network, verifier_name)));
    let file = match &o.data {
        Some(dir) => Some(BlockFile::open(Path::new(dir), profile.activation_height)?),
        None => None,
    };
    // the address first: a port already taken should not cost a replay of the block file
    let listener = TcpListener::bind(&o.listen).map_err(|e| format!("--listen {}: {e}", o.listen))?;
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("{}", profile_line(&profile, verifier_name));
    if verifier_name == "reject-all" {
        eprintln!(
            "note: every spend is refused (TRANSFER, BURN, LIST, a DEPLOY that burns); --verifier {} checks proofs",
            PlonkVerifier::NAME
        );
    }

    match (&o.rpc, &o.esplora) {
        (Some(url), _) => {
            let authorization = match (&o.rpc_user, &o.rpc_pass, &o.rpc_cookie) {
                (Some(user), Some(pass), _) => Some(basic_auth(user, pass)),
                (_, _, Some(path)) => {
                    let cookie = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                    let (user, pass) = cookie.trim().split_once(':').ok_or(format!("{path}: not a cookie file"))?;
                    Some(basic_auth(user, pass))
                }
                _ => None,
            };
            run_follower(CoreRpc::new(url, authorization), indexer, store, file, listener, address, o)
        }
        (_, Some(url)) => run_follower(Esplora::new(url), indexer, store, file, listener, address, o),
        _ => unreachable!("checked by parse_args"),
    }
}

fn run_follower<S: Source>(
    source: S,
    indexer: Indexer,
    store: Arc<RwLock<Store>>,
    file: Option<(BlockFile, Vec<sh20_indexer::follow::SourceBlock>)>,
    listener: TcpListener,
    address: std::net::SocketAddr,
    o: &Options,
) -> Result<(), String> {
    let held = file.as_ref().map_or(0, |(_, blocks)| blocks.len());
    let mut follower = Follower::new(source, indexer, store.clone(), file).map_err(|e| e.to_string())?;
    if let Some((height, _)) = follower.tip() {
        eprintln!("block file: {held} blocks, up to block {height}");
    }
    if o.network.is_none() {
        match follower.source().network() {
            Ok(Some(name)) => store.write().expect("store lock").set_network(&name),
            Ok(None) => {}
            Err(e) => eprintln!("source: {e}"),
        }
    }
    sh20_indexer::server::serve(listener, store);
    eprintln!("listening on http://{address}");

    let mut last_note = std::time::Instant::now();
    let fatal = follower.run(Duration::from_secs(o.poll), |f, step| match step {
        Ok(Step::Applied(height)) => {
            // one line for each block near the tip, one every few seconds while catching up
            if last_note.elapsed() >= Duration::from_secs(5) {
                eprintln!("block {height} {}", hex(&f.indexer().digest()));
                last_note = std::time::Instant::now();
            }
        }
        Ok(Step::RolledBack(height)) => eprintln!("reorg: block {height} undone"),
        Ok(Step::AtTip) => {}
        Err(message) => eprintln!("source: {message}; trying again"),
    });
    Err(fatal.to_string())
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
    let (verifier, verifier_name) = verifier_of(&o.verifier)?;
    let profile = Profile {
        activation_height: activation,
        deploy_burn: o.deploy_burn.expect("checked by parse_args"),
        anchor_window: o.window,
        anchor_min_depth: o.min_depth,
        deploy_maturity: o.maturity,
    };
    eprintln!("{}", profile_line(&profile, verifier_name));

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
    match if options.follow { follow(&options) } else { run(&options) } {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
