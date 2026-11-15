import { execFileSync } from 'node:child_process';
import { readUrlhausKey } from './urlhaus-client.mjs';
const [repo, file] = process.argv.slice(2);
if (!repo || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo) || !file) {
  console.error('Usage: node src/set-urlhaus-secret.mjs OWNER/REPOSITORY PATH_TO_KEY_FILE');
  process.exitCode = 1;
} else {
  try {
    const key = await readUrlhausKey({ URLHAUS_AUTH_KEY_FILE: file });
    execFileSync('gh', ['secret', 'set', 'URLHAUS_AUTH_KEY', '--repo', repo], {
      input: key, stdio: ['pipe', 'ignore', 'pipe'],
    });
    console.log('URLhaus Actions secret configured. The key was passed through stdin and was not logged.');
  } catch {
    console.error('Unable to configure the Actions secret. No key or raw CLI error was printed.');
    process.exitCode = 1;
  }
}
