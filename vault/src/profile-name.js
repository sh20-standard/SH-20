// Which profile of profile.js this page follows. 'test' in the source tree: the dev servers
// (dev/serve.js, dev/regtest.js), the tests and the CI. A release replaces this one file with
// 'signet' (build.js, `signet: true`), and refuses to while the signet's activation height is unset.
export const PROFILE_NAME = 'test';
