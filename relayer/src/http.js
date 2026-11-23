// The relayer's HTTP routes (docs/RELAYER.md §1): GET /info, POST /transfer, GET /transfer/:nf.
// A POST whose body is plain text needs no preflight, so a page on any origin can hand a transfer over.

const MAX_BODY = 4096; // an 830-byte envelope is 1,660 hex characters

export function relayerHandler(relayer, { onSubmitted = () => {} } = {}) {
  return async (req, res) => {
    const send = (code, v) => res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*' }).end(JSON.stringify(v));
    const { pathname } = new URL(req.url, 'http://relayer');
    try {
      if (req.method === 'GET' && pathname === '/info') return send(200, await relayer.info());
      if (req.method === 'POST' && pathname === '/transfer') {
        let body = '';
        for await (const chunk of req) {
          body += chunk;
          if (body.length > MAX_BODY) return send(413, { error: 'a TRANSFER is 830 bytes: this body is far longer' });
        }
        const r = await relayer.submit(body);
        send(r.code, r.body);
        if (r.code === 202) onSubmitted();
        return;
      }
      const m = pathname.match(/^\/transfer\/([0-9a-fA-F]{64})$/);
      if (req.method === 'GET' && m) {
        const s = relayer.status(m[1]);
        return s ? send(200, s) : send(404, { error: 'this relayer does not know that nullifier' });
      }
      return send(404, { error: 'not found: GET /info, POST /transfer, GET /transfer/:nf' });
    } catch (e) {
      return send(500, { error: e.message });
    }
  };
}
