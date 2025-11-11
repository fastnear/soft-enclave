export type JsonRpcRequest = { jsonrpc: "2.0"; id: string | number; method: string; params?: any };
export type JsonRpcResponse<T = any> = { jsonrpc: "2.0"; id: string | number | null; result?: T; error?: { code: number; message: string; data?: any } };
export type EgressPolicy = {
  allowHosts: string[];
  allowMethods: string[];
  maxReqBytes?: number;
  maxRespBytes?: number;
  requireHttps?: boolean;
};

function normalizeHost(u: URL) { return u.port ? `${u.hostname}:${u.port}` : u.hostname; }
function isLocal(u: URL) { return u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "::1"; }

export function makeEgressGuard(policy: EgressPolicy) {
  const allowedMethods = new Set(policy.allowMethods.map(m => m.toLowerCase()));
  const allowedHosts = new Set(policy.allowHosts);
  const maxReq = policy.maxReqBytes ?? 64 * 1024;
  const maxResp = policy.maxRespBytes ?? 1024 * 1024;
  const httpsRequired = policy.requireHttps ?? true;

  function assertUrl(url: string) {
    const u = new URL(url);
    if (httpsRequired && !isLocal(u) && u.protocol !== "https:") { throw new Error(`Non-HTTPS blocked: ${u.toString()}`); }
    const hostNorm = normalizeHost(u);
    if (!allowedHosts.has(hostNorm) && !allowedHosts.has(u.hostname)) { throw new Error(`Blocked host: ${hostNorm}`); }
    return u.toString();
  }

  function assertRequest(req: JsonRpcRequest) {
    const m = String(req.method || "").toLowerCase();
    if (!allowedMethods.has(m)) throw new Error(`Blocked method: ${req.method}`);
    const size = JSON.stringify(req).length;
    if (size > maxReq) throw new Error(`Request too large: ${size} bytes > ${maxReq}`);
  }

  async function readJsonCapped(res: Response, cap: number): Promise<any> {
    const reader = res.body?.getReader();
    if (!reader) return JSON.parse(await res.text());
    const chunks: Uint8Array[] = []; let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) { reader.cancel("cap exceeded").catch(()=>{}); throw new Error(`Response too large: > ${cap} bytes`); }
      chunks.push(value);
    }
    const buf = new Uint8Array(total); let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.length; }
    let s = ""; const CHUNK = 0x8000;
    for (let i = 0; i < buf.length; i += CHUNK) { s += String.fromCharCode.apply(null, Array.from(buf.subarray(i, i + CHUNK)) as any); }
    return JSON.parse(s);
  }

  async function postOnce(url: string, req: JsonRpcRequest): Promise<JsonRpcResponse> {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer"
    });
    const ok = res.ok;
    const data = await readJsonCapped(res, maxResp).catch(async () => {
      const t = await res.text();
      return { _raw: t.slice(0, 512) };
    });
    if (!ok) throw new Error(`HTTP ${res.status} ${res.statusText}: ${typeof data === 'string' ? data : JSON.stringify(data).slice(0,200)}`);
    return data;
  }

  async function post(url: string, req: JsonRpcRequest): Promise<JsonRpcResponse> {
    assertRequest(req);
    const safeUrl = assertUrl(url);
    try {
      return await postOnce(safeUrl, req);
    } catch (e) {
      const m = String(req.method || "").toLowerCase();
      if (m === "send_tx" && allowedMethods.has("broadcast_tx_commit")) {
        const p = req.params as any;
        const b64 = p && typeof p === "object" && "signed_tx_base64" in p ? p.signed_tx_base64 : null;
        if (b64) {
          const alt: JsonRpcRequest = { jsonrpc: "2.0", id: req.id, method: "broadcast_tx_commit", params: [b64] };
          return await postOnce(safeUrl, alt);
        }
      }
      throw e;
    }
  }

  return { post };
}
