const cookie = require("cookie");
const request = require("superagent");
const { get_url } = require("../utils");

const { get_conf, get_redis_subscriber } = require("../../node_utils");
const conf = get_conf();

// ── Cross-origin allowlist (Open Wings customization) ─────────────────────
// Vanilla Frappe enforces a strict Host == Origin check below. That breaks
// our deployment where external apps (NVO/AMS/FMS) live on their own
// per-tenant origins (e.g. nvo.org1.com) but connect to a shared Frappe
// socketio at hub.openwingsit.com.
//
// To keep Frappe generic (no app-specific names in this file), we read an
// optional allowlist from a fixed Redis key. Any Frappe app may populate it;
// when nothing populates it (the key is missing or empty), behavior is
// identical to vanilla Frappe — strict same-origin only.
//
// Population: Wings Hub's wings_hub/wings_hub/cors.py writes to this key
// whenever Organization Param's *_FRONTEND_URL rows change. See
// frappe-check-file-changes/documentation/0000011_changes_to_socket_functionality.md
// for the full picture and reproduction steps.
const CROSS_ORIGIN_REDIS_KEY = "socketio_cross_origin_allowlist";
const CROSS_ORIGIN_CACHE_TTL_MS = 30 * 1000; // 30s — refresh well below the
                                             // typical onboarding cadence.

let crossOriginCache = { origins: new Set(), expiresAt: 0 };
let redisClient = null;

async function getRedisClient() {
	if (redisClient) return redisClient;
	try {
		const client = get_redis_subscriber("redis_cache");
		client.on("error", () => {});  // swallow connection errors; we degrade
		                               // to "no allowlist" on failure
		await client.connect();
		redisClient = client;
	} catch (e) {
		// Couldn't connect — leave redisClient null so the next call retries.
	}
	return redisClient;
}

async function getCrossOriginAllowlist() {
	const now = Date.now();
	if (now < crossOriginCache.expiresAt) {
		return crossOriginCache.origins;
	}
	let origins = new Set();
	try {
		const client = await getRedisClient();
		if (client) {
			const raw = await client.get(CROSS_ORIGIN_REDIS_KEY);
			if (raw) {
				const parsed = JSON.parse(raw);
				if (Array.isArray(parsed)) origins = new Set(parsed);
			}
		}
	} catch (e) {
		// Bad JSON or transient Redis error — fall through to empty set, which
		// preserves the vanilla strict-same-origin behavior for this window.
	}
	crossOriginCache = { origins, expiresAt: now + CROSS_ORIGIN_CACHE_TTL_MS };
	return origins;
}

async function isOriginPermitted(host, origin) {
	if (host === get_hostname(origin)) return true;  // vanilla same-origin OK
	if (!origin) return false;
	const allow = await getCrossOriginAllowlist();
	return allow.has(origin);
}
// ── End cross-origin allowlist ────────────────────────────────────────────

function authenticate_with_frappe(socket, next) {
	let namespace = socket.nsp.name;
	namespace = namespace.slice(1, namespace.length); // remove leading `/`

	if (namespace != get_site_name(socket)) {
		next(new Error("Invalid namespace"));
	}

	const requestHost = get_hostname(socket.request.headers.host);
	const requestOrigin = socket.request.headers.origin;

	isOriginPermitted(requestHost, requestOrigin).then((permitted) => {
		if (!permitted) {
			next(new Error("Invalid origin"));
			return;
		}

		if (!socket.request.headers.cookie && !socket.request.headers.authorization) {
			next(
				new Error(
					"Missing cookie and authorization header. Either one needed for authentication."
				)
			);
			return;
		}

		let cookies = cookie.parse(socket.request.headers.cookie || "");
		let authorization_header = socket.request.headers.authorization;

		if (!cookies.sid && !authorization_header) {
			next(new Error("No authentication method used. Use cookie or authorization header."));
			return;
		}

		// Vanilla get_url() builds the validation URL from the request's
		// Origin header. For same-origin connections (Frappe Desk users at
		// the same hostname as socketio) that's correct — Origin points
		// back at Frappe HTTP. For cross-origin connections (external apps
		// like NVO/AMS/FMS at their own hostname) Origin points at the
		// external app, not Frappe — the self-callback would ECONNREFUSED.
		//
		// Detect cross-origin (Host hostname != Origin hostname, mirroring
		// the cross-origin gate above) and rebuild the URL using the local
		// webserver port. We explicitly set the Host header so Frappe HTTP
		// routes to the right multi-tenant site rather than its default.
		const reqHost = get_hostname(socket.request.headers.host);
		const reqOriginHost = get_hostname(socket.request.headers.origin);
		const isCrossOrigin = reqHost !== reqOriginHost;
		let authUrl;
		if (isCrossOrigin) {
			const port = conf.webserver_port || 8000;
			authUrl = `http://127.0.0.1:${port}/api/method/frappe.realtime.get_user_info`;
		} else {
			authUrl = get_url(socket, "/api/method/frappe.realtime.get_user_info");
		}

		let auth_req = request.get(authUrl);
		if (isCrossOrigin) {
			// Site routing — Frappe sees Host: 127.0.0.1 otherwise and
			// matches the default_site instead of the cross-origin site.
			auth_req = auth_req.set("Host", get_site_name(socket));
		}
		if (authorization_header) {
			auth_req = auth_req.set("Authorization", authorization_header);
		} else if (cookies.sid) {
			auth_req = auth_req.query({ sid: cookies.sid });
		}

		auth_req
			.type("form")
			.then((res) => {
				socket.user = res.body.message.user;
				socket.user_type = res.body.message.user_type;
				socket.sid = cookies.sid;
				socket.authorization_header = authorization_header;
				next();
			})
			.catch((e) => {
				next(new Error(`Unauthorized: ${e}`));
			});
	}).catch(() => {
		// Defensive: any error in the allowlist path falls back to "reject"
		// rather than accidentally letting an unauthorized origin through.
		next(new Error("Invalid origin"));
	});
}

function get_site_name(socket) {
	if (socket.site_name) {
		return socket.site_name;
	} else if (socket.request.headers["x-frappe-site-name"]) {
		socket.site_name = get_hostname(socket.request.headers["x-frappe-site-name"]);
	} else if (
		conf.default_site &&
		["localhost", "127.0.0.1"].indexOf(get_hostname(socket.request.headers.host)) !== -1
	) {
		socket.site_name = conf.default_site;
	} else if (socket.request.headers.origin) {
		socket.site_name = get_hostname(socket.request.headers.origin);
	} else {
		socket.site_name = get_hostname(socket.request.headers.host);
	}
	return socket.site_name;
}

function get_hostname(url) {
	if (!url) return undefined;
	if (url.indexOf("://") > -1) {
		url = url.split("/")[2];
	}
	return url.match(/:/g) ? url.slice(0, url.indexOf(":")) : url;
}

module.exports = authenticate_with_frappe;
