#!/usr/bin/ucode
/* Export imported VLESS nodes of one named subscription as share links. */
'use strict';
import { md5 } from 'digest';
import { cursor } from 'uci';
import { urlencode } from 'luci.http';

const section = ARGV[0];
const uci = cursor();
uci.load('homeproxy');
if (!section || uci.get('homeproxy', section) !== 'subscription_source')
	exit(1);

function to_vless_link(node) {
	let query = 'encryption=none';
	const params = {
		security: node.tls_reality === '1' ? 'reality' : (node.tls === '1' ? 'tls' : 'none'),
		type: node.transport || 'tcp',
		sni: node.tls_sni,
		pbk: node.tls_reality_public_key,
		sid: node.tls_reality_short_id,
		fp: node.tls_utls,
		flow: node.vless_flow,
		host: node.ws_host || node.http_host || node.httpupgrade_host,
		path: node.ws_path || node.http_path,
		serviceName: node.grpc_servicename
	};
	for (let key in keys(params))
		if (params[key])
			query += `&${key}=${urlencode(type(params[key]) === 'array' ? join(',', params[key]) : params[key])}`;
	const host = match(node.address, /:/) ? `[${node.address}]` : node.address;
	return `vless://${urlencode(node.uuid)}@${host}:${node.port}?${query}#${urlencode(node.label || node.address)}`;
}

const hash = md5(`source:${section}`);
uci.foreach('homeproxy', 'node', (node) => {
	if (node.grouphash !== hash || node.type !== 'vless' || !node.uuid || !node.address || !node.port)
		return;
	print(to_vless_link(node) + '\n');
});
