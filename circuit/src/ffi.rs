//! C ABI, for the WebAssembly build (browser wallets, the Node indexer) and for native callers.
//! No dependency on the host beyond linear memory: the host passes bytes in and reads bytes out, and
//! supplies the 32-byte seed of the prover's blinding randomness.
//!
//!   sh20_alloc(len) → ptr            sh20_free(ptr, len)
//!   sh20_verify(vk, vk_len, publics, proof, proof_len) → 1 valid | 0 invalid | −1 malformed key or inputs
//!   sh20_load_key(pk, pk_len) → key handle (0 on error)        the shipped proving key, digest checked
//!   sh20_keygen(srs, srs_len) → key handle (0 on error)        sh20_key_free(handle)
//!   sh20_vk(handle, out[712])        sh20_vk_digest(handle, out[32])
//!   sh20_prove(handle, witness[3232], seed[32], out[480]) → 1 proved | 0 witness rejected
//!                                                               the blinding scalars come from a generator seeded
//!                                                               with SHA-256("sh20/v0/blinding" ‖ seed ‖ witness)
//!   sh20_sample_witness(seed[32], out[3232])                    (benchmarks)
//!   sh20_threads(n) → threads in use                            starts the thread pool (threaded build only)
//!   sh20_reserve(bytes) → bytes reserved                        grows the heap once, up front (see below)
//!   sh20_pool(n) → threads                                     the calls that follow (load_key, prove) run on a
//!                                                               pool of n threads of their own, replacing the last
//!   sh20_timings(out[4 × f64])                                  seconds spent by the last proof in commitments,
//!                                                               transforms, the quotient and the rest (zeros
//!                                                               where the build has no clock)
//!
//! `publics` is nine 32-byte little-endian field elements in verifier order; the witness layout is
//! `SpendWitness::to_bytes`.

use crate::model::{SpendWitness, WITNESS_BYTES};
use crate::plonk::{self, keys::VK_BYTES, ProvingKey, Srs, VerifyingKey, PROOF_BYTES};
use crate::{fixture, keygen, load_key, prove_timed, verify, Fr, N_PUBLIC};
use std::sync::Mutex;

/// Timings of the last proof made through this interface.
static LAST: Mutex<[f64; 4]> = Mutex::new([0.0; 4]);

/// A thread pool that replaces the global one for the calls that follow (`sh20_pool`).
#[cfg(feature = "parallel")]
static POOL: Mutex<Option<std::sync::Arc<rayon::ThreadPool>>> = Mutex::new(None);

/// Runs `f` on the pool set by `sh20_pool`, or where it is called if there is none.
fn on_pool<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    #[cfg(feature = "parallel")]
    {
        let pool = POOL.lock().ok().and_then(|p| p.clone());
        if let Some(pool) = pool {
            return pool.install(f);
        }
    }
    f()
}

/// Makes the calls that follow run on a pool of `n` threads of their own, in place of the previous
/// such pool (whose threads end). Lets one instance be measured with several thread counts.
/// Returns the size of the pool; 1, and nothing happens, without the `parallel` feature.
#[no_mangle]
pub extern "C" fn sh20_pool(n: usize) -> usize {
    #[cfg(feature = "parallel")]
    {
        let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(n.max(1)).build() else { return 0 };
        let size = pool.current_num_threads();
        if let Ok(mut slot) = POOL.lock() {
            *slot = Some(std::sync::Arc::new(pool));
        }
        size
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = n;
        1
    }
}
use ark_std::rand::{rngs::StdRng, SeedableRng};

/// Starts the prover's thread pool with `n` threads and returns the number of threads in use.
/// Without the `parallel` feature there is one thread and this does nothing.
#[no_mangle]
pub extern "C" fn sh20_threads(n: usize) -> usize {
    #[cfg(feature = "parallel")]
    {
        // an error means the pool already exists: its size is what counts
        let _ = rayon::ThreadPoolBuilder::new().num_threads(n.max(1)).build_global();
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = n;
        1
    }
}

/// Grows the heap by `bytes` in one step and gives the block back to the allocator, so that the
/// allocations that follow fit without growing the memory again. Returns the bytes reserved, 0 if the
/// memory could not grow that far.
///
/// A measuring tool: nothing calls it by default. An engine that has not reserved address space
/// behind a WebAssembly memory grows it by allocating a larger block and copying the whole memory,
/// and the prover reaches its 224 MB in many steps. In JavaScriptCore's shell with
/// `--useWasmFastMemory=false` (`bench/jsc-bench.js`) that costs 0.5–1.2 s at key loading and
/// 2.4–3.1 s in the first proof, and one reservation of 240 MiB removes both. Browsers do not run
/// that way: on an iPhone (Safari, 2026-11-19) growing a memory to 224 MB in 223 steps takes 62 ms,
/// and the key loads and the first proof runs as fast without the reservation as with it (the test
/// page's `?auto=keyload`); the same in Chrome.
#[no_mangle]
pub extern "C" fn sh20_reserve(bytes: usize) -> usize {
    let mut block: Vec<u8> = Vec::new();
    match block.try_reserve_exact(bytes) {
        Ok(()) => block.capacity(),
        Err(_) => 0,
    }
}

unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    std::slice::from_raw_parts(ptr, len)
}

#[no_mangle]
pub extern "C" fn sh20_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `ptr` and `len` come from `sh20_alloc`.
#[no_mangle]
pub unsafe extern "C" fn sh20_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
}

/// # Safety
/// The pointers are valid for the given lengths; `publics` holds 9 × 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn sh20_verify(vk: *const u8, vk_len: usize, publics: *const u8, proof: *const u8, proof_len: usize) -> i32 {
    let Ok(vk) = VerifyingKey::from_bytes(bytes(vk, vk_len)) else { return -1 };
    let mut inputs = [Fr::from(0u64); N_PUBLIC];
    for (i, slot) in inputs.iter_mut().enumerate() {
        match plonk::fr_from_bytes(bytes(publics.add(i * 32), 32)) {
            Some(x) => *slot = x,
            None => return -1,
        }
    }
    verify(&vk, &inputs, bytes(proof, proof_len)) as i32
}

/// # Safety
/// `pk` is valid for `pk_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sh20_load_key(pk: *const u8, pk_len: usize) -> *mut ProvingKey {
    let data = bytes(pk, pk_len);
    match on_pool(|| load_key(data)) {
        Ok(pk) => Box::into_raw(Box::new(pk)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `srs` is valid for `srs_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sh20_keygen(srs: *const u8, srs_len: usize) -> *mut ProvingKey {
    let Ok(srs) = Srs::from_bytes(bytes(srs, srs_len)) else { return std::ptr::null_mut() };
    match keygen(&srs) {
        Ok(pk) => Box::into_raw(Box::new(pk)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `pk` comes from `sh20_keygen` and is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn sh20_key_free(pk: *mut ProvingKey) {
    if !pk.is_null() {
        drop(Box::from_raw(pk));
    }
}

/// # Safety
/// `pk` comes from `sh20_keygen`; `out` has room for 712 bytes.
#[no_mangle]
pub unsafe extern "C" fn sh20_vk(pk: *const ProvingKey, out: *mut u8) {
    std::ptr::copy_nonoverlapping((*pk).vk.to_bytes().as_ptr(), out, VK_BYTES);
}

/// # Safety
/// `pk` comes from `sh20_keygen`; `out` has room for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn sh20_vk_digest(pk: *const ProvingKey, out: *mut u8) {
    std::ptr::copy_nonoverlapping((*pk).vk.digest().as_ptr(), out, 32);
}

/// Domain tag of the hash that seeds the prover's generator.
pub const TAG_BLINDING: &[u8] = b"sh20/v0/blinding";

/// The seed of the generator the prover draws its blinding scalars from:
/// SHA-256("sh20/v0/blinding" ‖ seed ‖ witness), `seed` the host's 32 bytes and `witness` the 3,232
/// bytes it proves. The host's seed alone would give two witnesses the same eleven scalars if a
/// host ever used one seed twice, and the difference of the two proofs' commitments would then be
/// unblinded (docs/audit/2026-11-24-verifier.md, verifier-3). With the witness in the hash, one
/// seed and another witness give unrelated scalars, and one seed and one witness the same proof.
/// A host still owes a fresh seed to each proof: it is all that an observer cannot recompute.
pub fn blinding_seed(seed: &[u8; 32], witness: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new().chain_update(TAG_BLINDING).chain_update(seed).chain_update(witness).finalize().into()
}

/// # Safety
/// `pk` comes from `sh20_keygen`; `witness` holds 3,232 bytes, `seed` 32 fresh random bytes, and
/// `out` has room for 480 bytes.
#[no_mangle]
pub unsafe extern "C" fn sh20_prove(pk: *const ProvingKey, witness: *const u8, seed: *const u8, out: *mut u8) -> i32 {
    let witness = bytes(witness, WITNESS_BYTES);
    let Some(w) = SpendWitness::from_bytes(witness) else { return 0 };
    let mut rng = StdRng::from_seed(blinding_seed(bytes(seed, 32).try_into().unwrap(), witness));
    let key: &ProvingKey = &*pk;
    match on_pool(|| prove_timed(key, &w, &mut rng)) {
        Ok((proof, t)) => {
            std::ptr::copy_nonoverlapping(proof.as_ptr(), out, PROOF_BYTES);
            if let Ok(mut last) = LAST.lock() {
                *last = [t.msm, t.fft, t.quotient, t.other];
            }
            1
        }
        Err(_) => 0,
    }
}

/// # Safety
/// `out` has room for four f64 (32 bytes), not necessarily aligned.
#[no_mangle]
pub unsafe extern "C" fn sh20_timings(out: *mut u8) {
    let last = LAST.lock().map(|l| *l).unwrap_or([0.0; 4]);
    for (i, v) in last.iter().enumerate() {
        std::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), out.add(i * 8), 8);
    }
}

/// # Safety
/// `seed` holds 32 bytes; `out` has room for 3,232 bytes.
#[no_mangle]
pub unsafe extern "C" fn sh20_sample_witness(seed: *const u8, out: *mut u8) {
    let mut rng = StdRng::from_seed(bytes(seed, 32).try_into().unwrap());
    let w = fixture::transfer(&mut rng).to_bytes();
    std::ptr::copy_nonoverlapping(w.as_ptr(), out, WITNESS_BYTES);
}
