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

// Start iframe static server (on 8091) and Vite (host) concurrently.
run('node', ['enclave-server.js']); // Note: Could be adapted for iframe serving
run('npm', ['run', 'dev']);
