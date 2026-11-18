//! A proof on a pool that mixes fast and slow threads, to see how each phase of the prover copes
//! with the unequal cores of a phone.
//!
//!   cargo run --release --example slow_cores -- artifacts/spend.pk <fast> <slow> [runs]
//!
//! macOS on Apple silicon only. A thread of the background class is kept on the efficiency cores, at
//! their low clock; a thread of the user-interactive class goes to the performance cores. So `2 2`
//! stands for a phone with two fast cores and two slow ones, more unequal than a real one: a
//! background thread here runs at about a quarter of a fast one, a phone's small core at a third to a
//! half. Ask for no more slow threads than the machine has efficiency cores
//! (`sysctl hw.perflevel1.physicalcpu`), or they share them.
//!
//! Prints, for each proof, the seconds spent in commitments (msm), transforms (fft), the quotient and
//! the rest, and the proof-wide speed-up over one fast thread when a baseline is given with
//! `BASELINE=<seconds>`.

#[cfg(all(target_os = "macos", feature = "parallel"))]
fn main() {
    use rand_core::OsRng;
    use sh20_circuit::{fixture, load_key, prove_timed};

    extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
    const QOS_CLASS_BACKGROUND: u32 = 0x09;

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!("usage: slow_cores <spend.pk> <fast threads> <slow threads> [runs]");
        std::process::exit(2);
    }
    let fast: usize = args[1].parse().expect("fast threads");
    let slow: usize = args[2].parse().expect("slow threads");
    let runs: usize = args.get(3).map_or(2, |r| r.parse().expect("runs"));
    assert!(fast + slow >= 1, "at least one thread");

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(fast + slow)
        .start_handler(move |i| {
            let class = if i < fast { QOS_CLASS_USER_INTERACTIVE } else { QOS_CLASS_BACKGROUND };
            // SAFETY: sets the scheduling class of the calling thread, nothing else
            let status = unsafe { pthread_set_qos_class_self_np(class, 0) };
            assert_eq!(status, 0, "the scheduling class was refused");
        })
        .build()
        .expect("thread pool");

    let bytes = std::fs::read(&args[0]).expect("the proving key file");
    let start = std::time::Instant::now();
    let pk = pool.install(|| load_key(&bytes)).expect("the pinned proving key");
    let key_s = start.elapsed().as_secs_f64();

    let mut best = f64::MAX;
    for _ in 0..runs {
        let w = fixture::transfer(&mut OsRng);
        let start = std::time::Instant::now();
        let (_, t) = pool.install(|| prove_timed(&pk, &w, &mut OsRng)).expect("a proof");
        let total = start.elapsed().as_secs_f64();
        best = best.min(total);
        println!(
            "{fast} fast + {slow} slow: prove {total:.2} s = msm {:.2} + fft {:.2} + quotient {:.2} + other {:.2}; key {key_s:.2} s",
            t.msm, t.fft, t.quotient, t.other
        );
    }
    if let Some(base) = std::env::var("BASELINE").ok().and_then(|b| b.parse::<f64>().ok()) {
        println!("{fast} fast + {slow} slow: {:.2} times one fast thread", base / best);
    }
}

#[cfg(not(all(target_os = "macos", feature = "parallel")))]
fn main() {
    eprintln!("slow_cores needs macOS and the `parallel` feature");
}
