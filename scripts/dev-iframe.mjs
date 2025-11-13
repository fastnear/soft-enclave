import { spawn } from 'node:child_process';

const procs = [];
function run(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: 'inherit', shell: process.platform === 'win32', ...opts });
  procs.push(p);
  p.on('exit', (code) => {
    if (code !== 0) console.error(`${cmd} exited with ${code}`);
    for (const q of procs) {
      if (!q.killed) {
        try {
          process.platform === 'win32' ? spawn('taskkill', ['/PID', q.pid, '/T', '/F']) : q.kill('SIGINT');
        } catch {}
      }
    }
    process.exit(code ?? 0);
  });
  return p;
}

// Start iframe enclave server (on 3010) and Vite (host on 3000) concurrently.
// Set environment variables for proper configuration
run('node', ['enclave-server.js'], {
  env: {
    ...process.env,
    ENCLAVE_PORT: '3010',
    HOST_ORIGIN: 'http://localhost:3000'
  }
});
run('npm', ['run', 'dev']);
