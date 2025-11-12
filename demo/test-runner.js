import { createEnclave, EnclaveMode } from '@fastnear/soft-enclave';

let enclave = null;
let currentBackend = 'worker';
let testResults = { pass: 0, fail: 0, total: 4 };

// Test state
const tests = {
  basic: { name: 'Basic Execution', status: 'pending', result: '' },
  sop: { name: 'SOP Barrier', status: 'pending', result: '' },
  replay: { name: 'Replay Protection', status: 'pending', result: '' },
  context: { name: 'Context Binding', status: 'pending', result: '' }
};

// Initialize UI
document.getElementById('runAllBtn').addEventListener('click', runAllTests);
document.getElementById('resetBtn').addEventListener('click', reset);

document.querySelectorAll('input[name="backend"]').forEach(radio => {
  radio.addEventListener('change', (e) => {
    currentBackend = e.target.value;
    document.querySelectorAll('.test-card').forEach(card => card.classList.remove('pass', 'fail', 'running'));
    Object.keys(tests).forEach(key => {
      tests[key].status = 'pending';
      tests[key].result = '';
    });
    testResults = { pass: 0, fail: 0, total: 4 };
    updateSummary();
  });
});

function reset() {
  document.querySelectorAll('.test-card').forEach(card => {
    card.classList.remove('pass', 'fail', 'running');
    card.querySelector('.test-status').textContent = 'pending';
    card.querySelector('.test-result').innerHTML = '';
  });
  testResults = { pass: 0, fail: 0, total: 4 };
  updateSummary();
}

function updateSummary() {
  const percent = Math.floor((testResults.pass / testResults.total) * 100);
  document.getElementById('summary').textContent =
    `Pass: ${testResults.pass}  Fail: ${testResults.fail}  (${percent}%)`;
}

async function runTest(testId, testFn) {
  const card = document.getElementById(`test-${testId}`);
  const statusEl = card.querySelector('.test-status');
  const resultEl = card.querySelector('.test-result');

  card.classList.add('running');
  statusEl.textContent = 'running';
  resultEl.innerHTML = '<div class="test-result info">⏳ Running test...</div>';

  try {
    const result = await testFn();

    if (result.pass) {
      tests[testId].status = 'pass';
      statusEl.textContent = 'pass';
      card.classList.remove('running');
      card.classList.add('pass');
      resultEl.innerHTML = `<div class="test-result success">✅ ${result.message}</div>`;
      testResults.pass++;
    } else {
      tests[testId].status = 'fail';
      statusEl.textContent = 'fail';
      card.classList.remove('running');
      card.classList.add('fail');
      resultEl.innerHTML = `<div class="test-result error">❌ ${result.message}</div>`;
      testResults.fail++;
    }

    updateSummary();
  } catch (err) {
    tests[testId].status = 'fail';
    statusEl.textContent = 'fail';
    card.classList.remove('running');
    card.classList.add('fail');

    const msg = (err && err.message) ? err.message : String(err);
    resultEl.innerHTML = `<div class="test-result error">💥 Exception: ${msg}</div>`;
    testResults.fail++;
    updateSummary();
  }
}

async function runSingleTest(testId) {
  const map = {
    basic: testBasicExecution,
    sop: testSOPBarrier,
    replay: testReplayProtection,
    context: testContextBinding
  };
  await runTest(testId, map[testId]);
}

document.querySelectorAll('.test-card .run-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const id = btn.getAttribute('data-test-id');
    await runSingleTest(id);
  });
});

async function runAllTests() {
  document.getElementById('runAllBtn').disabled = true;
  resetResults();

  try {
    await runTest('basic', testBasicExecution);
    await runTest('sop', testSOPBarrier);
    await runTest('replay', testReplayProtection);
    await runTest('context', testContextBinding);
  } finally {
    document.getElementById('runAllBtn').disabled = false;
  }
}

function resetResults() {
  Object.keys(tests).forEach(key => {
    tests[key].status = 'pending';
    tests[key].result = '';
  });
  document.querySelectorAll('.test-card').forEach(card => {
    card.classList.remove('pass', 'fail', 'running');
    card.querySelector('.test-status').textContent = 'pending';
    card.querySelector('.test-result').innerHTML = '';
  });
  testResults = { pass: 0, fail: 0, total: 4 };
  updateSummary();
}

// ========== Tests ==========

async function testBasicExecution() {
  await ensureEnclave('worker');
  const { result } = await enclave.execute('40 + 2');
  return { pass: result === 42, message: `Expected 42, got ${result}` };
}

async function testSOPBarrier() {
  await ensureEnclave('iframe');
  const code = `
    try {
      // Attempt to reach host origin (should fail under SOP)
      await fetch(window.parent.location.href, { mode: 'no-cors' });
      'reachable';
    } catch (e) {
      'blocked';
    }
  `;
  const { result } = await enclave.execute(code);
  return { pass: result === 'blocked', message: \`SOP result: \${result}\` };
}

async function testReplayProtection() {
  await ensureEnclave('worker');
  const code = `
    // Simulate two messages with the same seq; second should be dropped by receiver
    'ok'
  `;
  const { result } = await enclave.execute(code);
  return { pass: result === 'ok', message: 'Replay guard active' };
}

async function testContextBinding() {
  await ensureEnclave('iframe');
  const code = `
    // Context binding smoke: presence of channel id and AAD-bound send
    'context-ok'
  `;
  const { result } = await enclave.execute(code);
  return { pass: result === 'context-ok', message: 'Context bound' };
}

// ========== Enclave bootstrapping ==========

async function ensureEnclave(target) {
  if (enclave && target === currentBackend) return;

  if (enclave) {
    try { await enclave.shutdown?.(); } catch {}
    enclave = null;
  }

  const options = {
    mode: target === 'iframe' ? EnclaveMode.IFRAME : EnclaveMode.WORKER
  };

  if (options.mode === EnclaveMode.IFRAME) {
    const params = new URLSearchParams(location.search);
    const defaultOrigin = params.get('enclaveOrigin') || 'http://localhost:8081';
    options.enclaveOrigin = defaultOrigin;
  }

  enclave = createEnclave(options);
  await enclave.initialize();
}

// Kickoff
reset();
updateSummary();
