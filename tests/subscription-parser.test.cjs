// Run: node --test tests/subscription-parser.test.cjs
// Executes parser functions extracted from the current Re:HomeProxy source.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'root/etc/homeproxy/scripts/update_subscriptions.uc'), 'utf8');
const helperSource = fs.readFileSync(path.join(__dirname, '..', 'root/etc/homeproxy/scripts/homeproxy.uc'), 'utf8');
const exportSource = fs.readFileSync(path.join(__dirname, '..', 'root/etc/homeproxy/scripts/export_subscription_links.uc'), 'utf8');
const nodeViewSource = fs.readFileSync(path.join(__dirname, '..', 'htdocs/luci-static/resources/view/homeproxy/node.js'), 'utf8');

function extract(name) {
  return extractFrom(source, name);
}
function extractFrom(content, name) {
  const start = content.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in source`);
  let depth = 0, body = content.indexOf('{', start);
  for (let i = body; i < content.length; i++) {
    if (content[i] === '{') depth++;
    if (content[i] === '}' && --depth === 0) return content.slice(start, i + 1);
  }
  throw new Error(`Unclosed function ${name}`);
}

// ucode's `value in array` means membership; JavaScript's `in` means index.
// ucode also iterates array values with `for (... in ...)`.
function adaptUcode(text) {
  return text.replace(/(\b\w+) in (\[[^\]]+\])/g, '$2.includes($1)')
    .replace(/for \(let ob in cfg\.outbounds\)/g, 'for (let ob of cfg.outbounds)')
    .replace(/ob\.protocol in skip/g, 'skip.includes(ob.protocol)')
    .replace(/proto in proxy_types/g, 'proxy_types.includes(proto)')
    .replace(/for \(let code in excluded\)/g, 'for (let code of excluded)')
    .replace(/for \(let i in keywords\)/g, 'for (let i of keywords)')
    .replace(/for \(let word in \(source\.exclude_keywords \|\| \[\]\)\)/g, 'for (let word of (source.exclude_keywords || []))')
    .replace(/for \(let header in \(headers \|\| \[\]\)\)/g, 'for (let header of (headers || []))')
    .replace(/for \(let key in keys\(params\)\)/g, 'for (let key of keys(params))')
    .replace(/code in \(source\.exclude_countries \|\| \[\]\)/g, '(source.exclude_countries || []).includes(code)');
}

const sandbox = {
  type: x => Array.isArray(x) ? 'array' : x === null ? 'null' : typeof x,
  sing_features: {with_utls: true, with_quic: true},
  log: () => {},
  sprintf: (format, value) => format.replace('%s', value),
  match: (value, regex) => regex.test(value),
  index: (value, needle) => value.indexOf(needle),
  uchr: (...codes) => String.fromCodePoint(...codes),
  ord: (value, at = 0) => value.charCodeAt(at),
  regexp: value => new RegExp(value),
  lc: value => value.toLowerCase(),
  isEmpty: value => !value || (Array.isArray(value) && !value.length),
  filter_mode: 'disabled',
  filter_keywords: [],
};
vm.createContext(sandbox);
vm.runInContext(adaptUcode(extract('parse_xray_outbound') + '\n' + extract('parse_xray_config') + '\n' + extract('filter_check')), sandbox);

function profile(remarks, address = 'edge.example') {
  return {remarks, outbounds: [
    {tag: 'direct', protocol: 'freedom'},
    {tag: 'proxy', protocol: 'vless', settings: {vnext: [{address, port: 443,
      users: [{id: '11111111-1111-4111-8111-111111111111', flow: 'xtls-rprx-vision'}]}]},
      streamSettings: {network: 'tcp', security: 'reality', realitySettings: {
        serverName: 'front.example', publicKey: 'synthetic-key', shortId: 'abcd', fingerprint: 'chrome'}}}
  ]};
}

test('current Xray JSON parser maps VLESS REALITY fields', () => {
  const node = sandbox.parse_xray_config(profile('Germany'));
  assert.equal(node.label, 'Germany');
  assert.equal(node.type, 'vless');
  assert.equal(node.address, 'edge.example');
  assert.equal(node.port, '443');
  assert.equal(node.uuid, '11111111-1111-4111-8111-111111111111');
  assert.equal(node.tls_reality_public_key, 'synthetic-key');
  assert.equal(node.tls_reality_short_id, 'abcd');
  assert.equal(node.tls_sni, 'front.example');
  assert.equal(node.vless_flow, 'xtls-rprx-vision');
});

test('current parser selects proxy outbound and rejects unrelated configs', () => {
  assert.equal(sandbox.parse_xray_config({remarks: 'empty', outbounds: [{protocol: 'freedom'}]}), null);
  assert.equal(sandbox.parse_xray_config(profile('Germany')).type, 'vless');
});

test('current parser maps websocket transport from Xray config', () => {
  const input = profile('Websocket');
  input.outbounds[1].streamSettings.network = 'ws';
  input.outbounds[1].streamSettings.wsSettings = {headers: {Host: 'cdn.example'}, path: '/ws'};
  const node = sandbox.parse_xray_config(input);
  assert.equal(node.transport, 'ws');
  assert.equal(node.ws_host, 'cdn.example');
  assert.equal(node.ws_path, '/ws');
});

test('source filter excludes configured flags, Auto and name patterns', () => {
  const source = {exclude_countries: ['RU', 'BY'], exclude_auto: '1',
    exclude_keywords: ['expired'], filter_mode: 'blacklist', filter_keywords: ['Trial']};
  assert.equal(sandbox.filter_check('🇷🇺 Moscow', source), true);
  assert.equal(sandbox.filter_check('🇪🇺 Auto', source), true);
  assert.equal(sandbox.filter_check('🇩🇪 Trial', source), true);
  assert.equal(sandbox.filter_check('🇩🇪 EXPIRED', source), true);
  assert.equal(sandbox.filter_check('🇩🇪 Berlin', source), false);
});

test('wget helper passes all headers and rejects line injection', () => {
  const calls = [];
  const http = {
    type: x => typeof x,
    match: (value, regex) => regex.test(value),
    shellQuote: value => `'${value.replaceAll("'", "'\\''")}'`,
    executeCommand: command => { calls.push(command); return {exitcode: 0, stdout: 'ok'}; },
    HP_DIR: '/etc/homeproxy',
    trim: value => value.trim(),
    substr: (value, at) => value.slice(at),
    index: (value, needle) => value.indexOf(needle),
  };
  vm.createContext(http);
  vm.runInContext(adaptUcode([
    extractFrom(helperSource, 'wGETResult'),
    extractFrom(helperSource, 'wGET')
  ].join('\n').replaceAll('export function', 'function')), http);
  assert.equal(http.wGET('https://example.test/sub', 'Custom/1', ['x-hwid: synthetic', 'X-Token: a b'], 'system', ''), 'ok');
  assert.match(calls[0], /--header 'x-hwid: synthetic'/);
  assert.match(calls[0], /--header 'X-Token: a b'/);
  assert.equal(http.wGET('https://example.test/sub', 'Custom/1', ['X-Token: ok\r\nInjected: yes'], 'system', ''), null);
  assert.equal(http.wGET('https://example.test/sub', 'Custom/1', ['User-Agent: v2rayNG/1.10.5'], 'system', ''), 'ok');
  assert.match(calls[1], /fetch_subscription\.sh 'system' '[^']+' 'v2rayNG\/1\.10\.5'/);
  assert.doesNotMatch(calls[1], /--header 'User-Agent:/);
  assert.equal(calls.length, 2);
  assert.doesNotMatch(helperSource, /\.includes\(/);
});

test('exporter assembles a VLESS REALITY share link from imported node', () => {
  const context = {
    urlencode: encodeURIComponent,
    type: x => Array.isArray(x) ? 'array' : typeof x,
    keys: Object.keys,
    join: (separator, values) => values.join(separator),
    match: (value, regex) => regex.test(value),
  };
  vm.createContext(context);
  vm.runInContext(adaptUcode(extractFrom(exportSource, 'to_vless_link')), context);
  const node = sandbox.parse_xray_config(profile('🇩🇪 Germany'));
  const link = context.to_vless_link(node);
  const parsed = new URL(link);
  assert.equal(parsed.protocol, 'vless:');
  assert.equal(parsed.hostname, 'edge.example');
  assert.equal(parsed.searchParams.get('security'), 'reality');
  assert.equal(parsed.searchParams.get('pbk'), 'synthetic-key');
  assert.equal(parsed.searchParams.get('sid'), 'abcd');
  assert.equal(parsed.searchParams.get('flow'), 'xtls-rprx-vision');
});

test('optional subscription fields accept an empty value', () => {
  assert.match(nodeViewSource, /return !value \|\| sourceTypes\.includes\(value\)/);
  assert.match(nodeViewSource, /return !value \|\| \/\^\[A-Z\]\{2\}\$\//);
  assert.match(nodeViewSource, /if \(!value\) return true;[\s\S]*new RegExp\(value\)/);
  assert.match(nodeViewSource, /sourceSection\.anonymous = true/);
});
