const ORIGIN = new URL(document.referrer || 'http://localhost:8080').origin;
const origPost = MessagePort.prototype.postMessage;
MessagePort.prototype.postMessage = function(msg: any, transfer?: any) {
  if (msg?.type === 'ciphertext-result') {
    const p = msg.payload;
    const ok = p && Array.isArray(p.iv) && Array.isArray(p.ciphertext);
    if (!ok) throw new Error('ciphertext-result schema violation');
  } else if (msg?.type === 'error') {
    // allowed
  } else {
    throw new Error('plaintext egress blocked');
  }
  return origPost.call(this, msg, transfer);
};

const winPM = window.postMessage;
// @ts-ignore - Intentionally overriding window.postMessage for egress guard
window.postMessage = function(msg: any, targetOrigin: any, transfer?: any) {
  if (targetOrigin !== ORIGIN) throw new Error('unexpected target origin');
  // @ts-ignore - Call signature intentionally simplified for egress guard
  return winPM.call(window, msg, targetOrigin, transfer);
};
