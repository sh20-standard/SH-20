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
//!   sh20_sample_witness(seed[32], out[3232])                    (benchmarks)
//!   sh20_threads(n) → threads in use                            starts the thread pool (threaded build only)
//!
//! `publics` is nine 32-byte little-endian field elements in verifier order; the witness layout is
//! `SpendWitness::to_bytes`.

use crate::model::{SpendWitness, WITNESS_BYTES};
use crate::plonk::{self, keys::VK_BYTES, ProvingKey, Srs, VerifyingKey, PROOF_BYTES};
use crate::{fixture, keygen, load_key, prove, verify, Fr, N_PUBLIC};
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
    match load_key(bytes(pk, pk_len)) {
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

/// # Safety
/// `pk` comes from `sh20_keygen`; `witness` holds 3,232 bytes, `seed` 32 fresh random bytes, and
/// `out` has room for 480 bytes.
#[no_mangle]
pub unsafe extern "C" fn sh20_prove(pk: *const ProvingKey, witness: *const u8, seed: *const u8, out: *mut u8) -> i32 {
    let Some(w) = SpendWitness::from_bytes(bytes(witness, WITNESS_BYTES)) else { return 0 };
    let mut rng = StdRng::from_seed(bytes(seed, 32).try_into().unwrap());
    match prove(&*pk, &w, &mut rng) {
        Ok(proof) => {
            std::ptr::copy_nonoverlapping(proof.as_ptr(), out, PROOF_BYTES);
            1
        }
        Err(_) => 0,
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
