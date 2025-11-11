export type ViewCall = { rpcUrl: string; contractId: string; methodName: string; args?: Record<string, any>; finality?: "optimistic" | "final"; id?: string | number; };

export type SignAndSendParams = {
  rpcUrl: string;
  signerId: string;
  receiverId: string;
  methodName: string;
  args: Record<string, any>;
  gas: string;
  deposit: string;
  privateKey: string; // ed25519:base58 format
  id?: string | number;
};

function toBase64(u8: Uint8Array): string {
  let s = ""; const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) s += String.fromCharCode.apply(null, Array.from(u8.subarray(i, i + CHUNK)) as any);
  return btoa(s);
}

export function makeViewFunctionRequest(v: ViewCall) {
  const id = v.id ?? Math.random().toString(36).slice(2);
  const args_bytes = v.args ? new TextEncoder().encode(JSON.stringify(v.args)) : new Uint8Array();
  const args_base64 = args_bytes.length ? toBase64(args_bytes) : "";
  const req = { jsonrpc: "2.0" as const, id, method: "query", params: { request_type: "call_function", account_id: v.contractId, method_name: v.methodName, args_base64, finality: v.finality ?? "optimistic" } };
  return { url: v.rpcUrl, req };
}

export function makeAccessKeyRequest(params: { rpcUrl: string; accountId: string; publicKey: string; id?: string | number }) {
  const id = params.id ?? Math.random().toString(36).slice(2);
  const req = { jsonrpc: "2.0" as const, id, method: "query", params: { request_type: "view_access_key", account_id: params.accountId, public_key: params.publicKey, finality: "final" } };
  return { url: params.rpcUrl, req };
}

export function makeBlockRequest(params: { rpcUrl: string; finality: "final" | "optimistic"; id?: string | number }) {
  const id = params.id ?? Math.random().toString(36).slice(2);
  const req = { jsonrpc: "2.0" as const, id, method: "block", params: { finality: params.finality } };
  return { url: params.rpcUrl, req };
}

export function makeSendTransactionRequest(params: { rpcUrl: string; signedTransaction: string; id?: string | number }) {
  const id = params.id ?? Math.random().toString(36).slice(2);
  const req = { jsonrpc: "2.0" as const, id, method: "send_tx", params: { signed_tx_base64: params.signedTransaction } };
  return { url: params.rpcUrl, req };
}
