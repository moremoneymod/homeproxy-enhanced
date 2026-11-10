// Local behavioral harness for update_subscriptions.uc, without OpenWrt modules.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');

const source = fs.readFileSync(path.join(__dirname, '..', 'root/etc/homeproxy/scripts/update_subscriptions.uc'), 'utf8');
const nodeView = fs.readFileSync(path.join(__dirname, '..', 'htdocs/luci-static/resources/view/homeproxy/node.js'), 'utf8');

test('named sources use a persisted v2rayNG User-Agent by default', () => {
  assert.match(source, /source\.user_agent \|\| 'v2rayNG\/1\.10\.5'/);
  assert.match(nodeView, /sourceOption\.default = 'v2rayNG\/1\.10\.5'/);
});

function extract(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  if (name === 'main') return source.slice(start, source.indexOf('\nif (!isEmpty(sources))', start)).trim();
  const body = source.indexOf('{', start);
  let depth = 0;
  for (let i = body; i < source.length; i++) {
    if (source[i] === '{') depth++;
    if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
  }
  throw new Error(`Missing closing brace: ${name}`);
}
function adapt(text) {
  return text
    .replace(/for \(let (source|node|nodes) in (sources|nodes|node_result)\)/g, 'for (let $1 of $2)')
    .replace(/for \(let ob in cfg\.outbounds\)/g, 'for (let ob of cfg.outbounds)')
    .replace(/for \(let cfg in configs\)/g, 'for (let cfg of configs)')
    .replace(/for \(let ob in \(cfg\.outbounds \|\| \[\]\)\)/g, 'for (let ob of (cfg.outbounds || []))')
    .replace(/for \(let code in excluded\)/g, 'for (let code of excluded)')
    .replace(/for \(let i in keywords\)/g, 'for (let i of keywords)')
    .replace(/for \(let word in \(source\.exclude_keywords \|\| \[\]\)\)/g, 'for (let word of (source.exclude_keywords || []))')
    .replace(/ob\.protocol in skip/g, 'skip.includes(ob.protocol)')
    .replace(/ob\.protocol in (\[[^\]]+\])/g, '$1.includes(ob.protocol)')
    .replace(/proto in proxy_types/g, 'proxy_types.includes(proto)')
    .replace(/config\.type in \['vless', 'vmess'\]/g, "['vless', 'vmess'].includes(config.type)")
    .replace(/config\.type in source\.include_types/g, 'source.include_types.includes(config.type)')
    .replace(/\(security in \['tls', 'xtls', 'reality'\]\)/g, "(['tls', 'xtls', 'reality'].includes(security))");
}

function fixture(label) {
  return [{remarks: label, outbounds: [{tag: 'proxy', protocol: 'vless',
    settings: {vnext: [{address: 'edge.example', port: 443, users: [{id: 'synthetic-uuid'}]}]},
    streamSettings: {network: 'tcp', security: 'reality',
      realitySettings: {serverName: 'front.example', publicKey: 'synthetic-key'}}}]}];
}

function harness(response) {
  const state = {
    config: {'.type': 'homeproxy', main_node: 'nil', main_udp_node: 'same'},
    subscription: {'.type': 'homeproxy'},
    provider: {'.type': 'subscription_source', label: 'Provider', url: 'https://example.test/sub'},
    route: {'.type': 'routing_node', node: 'urltest', urltest_subscription: 'provider', urltest_nodes: []},
  };
  const logs = [];
  const uci = {
    get: (_config, section, option) => option ? state[section]?.[option] : state[section]?.['.type'],
    get_all: (_config, section) => state[section],
    set: (_config, section, option, value) => {
      logs.push(`set ${section}.${option}=${value}`);
      if (value === undefined) state[section] = {'.type': option};
      else (state[section] ||= {'.type': 'node'})[option] = value;
    },
    delete: (_config, section, option) => {
      logs.push(`delete ${section}.${option}`);
      if (!option) delete state[section];
      else if (!option.startsWith('.')) delete state[section]?.[option];
    },
    foreach: (_config, kind, callback) => {
      for (const [name, value] of Object.entries({...state}))
        if (value['.type'] === kind) callback({...value, '.name': name});
    },
    get_first: (_config, kind) => Object.keys(state).find(name => state[name]['.type'] === kind),
    commit: () => {},
  };
  const env = {
    uci, sources: [{...state.provider, '.name': 'provider'}],
    node_cache: {}, node_result: [],
    uciconfig: 'homeproxy', ucimain: 'config', ucinode: 'node',
    main_node: 'nil', main_udp_node: 'same', via_proxy: '1',
    allow_insecure: '0', packet_encoding: 'xudp', filter_mode: 'disabled', filter_keywords: [], user_agent: null,
    sing_features: {with_utls: true, with_quic: true},
    wGET: url => Object.hasOwn(response, url) ? response[url] : response.current,
    log: message => logs.push(message), init_action: () => {},
    md5: value => crypto.createHash('md5').update(value).digest('hex'),
    isEmpty: value => !value || value === 'nil' || (Array.isArray(value) && !value.length) ||
      (typeof value === 'object' && !Object.keys(value).length),
    type: value => Array.isArray(value) ? 'array' : typeof value,
    match: (value, pattern) => String(value).match(pattern),
    trim: value => value.trim(),
    json: JSON.parse,
    length: value => Array.isArray(value) || typeof value === 'string' ? value.length : Object.keys(value || {}).length,
    map: (items, callback) => items.map(callback), filter: (items, callback) => (items || []).filter(callback),
    keys: Object.keys, push: (items, value) => items.push(value),
    sprintf: (format, ...args) => format === '%J' ? JSON.stringify(args[0]) :
      args.reduce((text, value) => text.replace('%s', value), format),
    replace: (value, pattern, replacement) => value.replace(pattern, replacement),
    index: (value, needle) => value.indexOf(needle),
    uchr: (...codes) => String.fromCodePoint(...codes),
    ord: (value, index = 0) => value.charCodeAt(index),
    regexp: value => new RegExp(value),
    lc: value => value.toLowerCase(),
    validation: () => true,
    parse_uri: value => value,
    decodeBase64Str: () => null,
    split: (value, separator) => value.split(separator),
    now: 1234567,
  };
  vm.createContext(env);
  const functions = ['filter_check', 'parse_xray_outbound', 'parse_xray_config', 'parse_xray_subscription', 'main'];
  vm.runInContext(adapt(functions.map(extract).join('\n')), env);
  return {state, env, logs};
}

test('update imports nodes, keeps ID across label changes, and syncs routing URLTest', () => {
  const response = {current: JSON.stringify(fixture('Germany'))};
  const {state, env, logs} = harness(response);
  env.main();
  let nodes = Object.entries(state).filter(([, value]) => value['.type'] === 'node');
  assert.equal(nodes.length, 1, JSON.stringify({state, logs}));
  const id = nodes[0][0];
  assert.equal(state.route.urltest_nodes[0], id);
  response.current = JSON.stringify(fixture('Berlin'));
  env.node_result.length = 0; // each real update starts a new ucode process
  env.node_cache = {};
  env.main();
  nodes = Object.entries(state).filter(([, value]) => value['.type'] === 'node');
  assert.equal(nodes.length, 1, JSON.stringify({state, logs}));
  assert.equal(nodes[0][0], id);
  assert.equal(nodes[0][1].label, 'Berlin');
  assert.equal(state.route.urltest_nodes[0], id);
});

test('failed fetch retains imported nodes and URLTest membership', () => {
  const response = {current: JSON.stringify(fixture('Germany'))};
  const {state, env} = harness(response);
  env.main();
  const before = JSON.stringify(state);
  response.current = null;
  env.node_result.length = 0;
  env.node_cache = {};
  env.main();
  assert.equal(JSON.stringify(state), before);
});

test('one failed source does not remove its nodes when another source succeeds', () => {
  const firstUrl = 'https://example.test/sub';
  const secondUrl = 'https://second.test/sub';
  const response = {
    [firstUrl]: JSON.stringify(fixture('First')),
    [secondUrl]: JSON.stringify(fixture('Second')),
  };
  const {state, env} = harness(response);
  state.second = {'.type': 'subscription_source', label: 'Second', url: secondUrl};
  env.sources.push({...state.second, '.name': 'second'});
  env.main();
  assert.equal(Object.values(state).filter(value => value['.type'] === 'node').length, 2);
  response[firstUrl] = JSON.stringify(fixture('First updated'));
  response[secondUrl] = null;
  env.node_result.length = 0;
  env.node_cache = {};
  env.main();
  const labels = Object.values(state).filter(value => value['.type'] === 'node').map(value => value.label).sort();
  assert.deepEqual(labels, ['First updated', 'Second']);
});

test('all mode imports additional compatible Xray outbounds', () => {
  const configs = fixture('Germany');
  configs[0].outbounds.push({tag: 'backup', protocol: 'vless',
    settings: {vnext: [{address: 'backup.example', port: 8443, users: [{id: 'second-uuid'}]}]},
    streamSettings: {network: 'tcp', security: 'reality',
      realitySettings: {serverName: 'front.example', publicKey: 'synthetic-key'}}});
  const response = {current: JSON.stringify(configs)};
  const {state, env} = harness(response);
  env.sources[0].xray_outbound_mode = 'all';
  env.main();
  const labels = Object.values(state).filter(value => value['.type'] === 'node').map(value => value.label).sort();
  assert.deepEqual(labels, ['Germany', 'Germany (backup)']);
});

test('same provider labels do not overwrite different servers', () => {
  const profiles = fixture('Same');
  const second = fixture('Same')[0];
  second.outbounds[0].settings.vnext[0].address = 'other.example';
  profiles.push(second);
  const {state, env} = harness({current: JSON.stringify(profiles)});
  env.main();
  const nodes = Object.values(state).filter(value => value['.type'] === 'node');
  assert.equal(nodes.length, 2);
  assert.deepEqual(nodes.map(n => n.address).sort(), ['edge.example', 'other.example']);
});

test('protocol filter can keep only VLESS nodes', () => {
  const profiles = fixture('VLESS');
  const trojan = {remarks: 'Trojan', outbounds: [{tag: 'proxy', protocol: 'trojan',
    settings: {servers: [{address: 'trojan.example', port: 443, password: 'synthetic'}]}}]};
  profiles.push(trojan);
  const {state, env} = harness({current: JSON.stringify(profiles)});
  env.sources[0].include_types = ['vless'];
  env.main();
  const nodes = Object.values(state).filter(value => value['.type'] === 'node');
  assert.deepEqual(nodes.map(n => n.type), ['vless']);
});

test('filter yielding no nodes preserves the last successful subscription', () => {
  const response = {current: JSON.stringify(fixture('Germany'))};
  const {state, env} = harness(response);
  env.main();
  const before = JSON.stringify(state.route.urltest_nodes);
  env.sources[0].exclude_keywords = ['Germany'];
  env.node_result.length = 0;
  env.node_cache = {};
  assert.equal(env.main(), false);
  assert.equal(Object.values(state).filter(value => value['.type'] === 'node').length, 1);
  assert.equal(JSON.stringify(state.route.urltest_nodes), before);
});

test('main URLTest follows the selected subscription', () => {
  const {state, env} = harness({current: JSON.stringify(fixture('Main'))});
  state.config.main_node = 'urltest';
  state.config.main_urltest_subscription = 'provider';
  env.main_node = 'urltest';
  env.main();
  const id = Object.entries(state).find(([, value]) => value['.type'] === 'node')[0];
  assert.equal(state.config.main_urltest_nodes[0], id);
});
