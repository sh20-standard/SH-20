# Phone test page

A static page that proves a sample SH-20 spend on the device that opens it and reports the timings:
download, key loading, each proof, verification, memory. Nothing is sent anywhere; the result is
copied by hand.

It answers the question the laptop cannot: how long a transfer takes to prove on a phone.

## Build and try it

```sh
rustup target add wasm32-unknown-unknown wasm32-wasip1-threads   # once
./build.sh              # web/dist/: the page, both WebAssembly builds, the proving key (10 MB)
node serve.mjs          # http://localhost:8080, with the isolation headers
node check.mjs          # the page in headless Chrome, for each way it can be served
node check.mjs --url https://…   # the same check against the page as served somewhere else
```

## Put it in front of a phone

The page measures all cores only where the browser grants shared memory, which needs a secure
context (https, or localhost) and cross-origin isolation.

| How it is served | What the phone can measure |
| --- | --- |
| `node serve.mjs`, phone on the same Wi-Fi, `http://<computer>:8080` | one thread only: plain http is not a secure context |
| the same server behind an https tunnel | all cores: the server sends the headers |
| `dist/` on any https static host | all cores: `sw.js` adds the headers the host does not send, after one automatic reload |

`dist/` is self-contained and loads nothing from another origin. A host that can set headers should
send `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` on
every file, and `application/wasm` for `.wasm`.

## What to do on the phone

1. Open the page and read "This device": it says whether shared memory is available.
2. Tap **Measure on all cores**, then **Measure on one thread**. Keep the screen on and the tab in
   front; a phone slows or stops a tab in the background.
3. Tap **Copy the result** after each run and send both back, with the model of the phone.

Adding `?auto=threads&runs=3` to the address starts a run by itself (`auto=single` for one thread,
`threads=4` to fix the pool size).

If a run fails, the page says so. The likely cause on a phone is memory: the prover needs about
230 MB.

## Files

| File | What |
| --- | --- |
| `index.html`, `app.js` | the page |
| `prover-worker.js` | the prover, in a Worker, for either build |
| `thread-worker.js` | one thread of the pool |
| `host.js` | what the threaded build needs from its host: shared memory, the few WASI calls, thread start |
| `sw.js` | the service worker that stands in for the isolation headers |
| `serve.mjs`, `check.mjs`, `build.sh` | local server, headless-Chrome check, assembly of `dist/` |

How the threads work: every thread is a Worker with its own instance of the same module on one
shared memory. The module asks for a thread through the import `wasi.thread-spawn`; the Worker that
receives the call posts the request to the page, which creates the new Worker. A wallet embeds
`host.js` and the two workers the same way.
