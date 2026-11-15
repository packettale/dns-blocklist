import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { mkdir, appendFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import {hostingReport} from './verify-output.mjs';

const root = process.cwd(), dist = join(root, 'dist');
const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore','pipe','pipe'] }).trim();

if (process.argv[2] === 'restore') {
  await mkdir(dist, { recursive: true });
  const check = spawnSync('git', ['ls-remote','--exit-code','origin','refs/heads/feeds'], { cwd: root, encoding:'utf8' });
  if (check.status === 2) console.log('First publication: no previous feed branch.');
  else {
    if (check.status !== 0) throw new Error('Could not check previous publication: '+check.stderr);
    git(['fetch','--depth=1','origin','refs/heads/feeds:refs/remotes/origin/feeds']);
    const archive = spawn('git', ['archive','origin/feeds'], { cwd:root, stdio:['ignore','pipe','pipe'] });
    const extract = spawn('tar', ['-xf','-','-C',dist], { cwd:root, stdio:['pipe','ignore','pipe'] });
    const done = process => new Promise((accept,reject) => {let error='';process.stderr.on('data',x=>error+=x);process.on('error',reject);process.on('close',code=>code===0?accept():reject(new Error(error||'Snapshot restore failed')));});
    await Promise.all([pipeline(archive.stdout,extract.stdin),done(archive),done(extract)]);
    console.log('Previous published snapshot restored.');
  }
} else if (process.argv[2] === 'publish') {
  const capacity=await hostingReport(dist);
  if(capacity.overGitFileLimit.length||capacity.overPagesSiteLimit)throw Error('Complete feeds exceed GitHub hosting limits. Use the server worker; publication stopped before writing any remote files.');
  await mkdir(join(root,'.cache'), { recursive:true });
  const index = join(root,'.cache','publish-index');
  const env = { ...process.env, GIT_INDEX_FILE:index, GIT_AUTHOR_NAME:'DNS-IP-Blocklist updater', GIT_AUTHOR_EMAIL:'41898282+github-actions[bot]@users.noreply.github.com', GIT_COMMITTER_NAME:'DNS-IP-Blocklist updater', GIT_COMMITTER_EMAIL:'41898282+github-actions[bot]@users.noreply.github.com' };
  const indexGit = args => execFileSync('git', [`--git-dir=${join(root,'.git')}`,`--work-tree=${dist}`,...args], {cwd:dist,env,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  indexGit(['read-tree','--empty']); indexGit(['add','--all','--','.']);
  const tree = indexGit(['write-tree']);
  let parent; try {parent=git(['rev-parse','--verify','origin/feeds']);} catch {}
  let changed = true;
  if (parent && git(['rev-parse',`${parent}^{tree}`]) === tree) changed=false;
  if (changed) {
    const commit=indexGit(['commit-tree',tree,...(parent?['-p',parent]:[]),'-m','Update categorized DNS and IP feeds']);
    git(['push','origin',`${commit}:refs/heads/feeds`]);
    console.log(`Published feed snapshot ${commit}`);
  } else console.log('No feed or site changes; publication preserved.');
  if(process.env.GITHUB_OUTPUT)await appendFile(process.env.GITHUB_OUTPUT,`changed=${changed}\n`);
} else throw new Error('Use restore or publish');
