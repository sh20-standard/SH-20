// Same mapping as the import map in index.html: node:crypto → the vault shim.
const SHIM = new URL('../../src/shim/node-crypto.js', import.meta.url).href;
export async function resolve(specifier, context, next) {
  if (specifier === 'node:crypto' || specifier === 'crypto') return { url: SHIM, shortCircuit: true };
  return next(specifier, context);
}
