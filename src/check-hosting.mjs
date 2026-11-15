import {hostingReport} from './verify-output.mjs';
const report=await hostingReport(process.argv[2]||'dist');
console.log(`${report.files} public files; ${(report.bytes/1024/1024).toFixed(1)} MiB.`);
if(report.overGitFileLimit.length||report.overPagesSiteLimit){
  console.error('Complete output exceeds GitHub raw-file or Pages hosting limits. Use the always-on server worker for the full catalog; no feeds have been silently omitted.');
  for(const file of report.overGitFileLimit)console.error(`${file.path}: ${(file.bytes/1024/1024).toFixed(1)} MiB (Git limit: 100 MiB)`);
  if(report.overPagesSiteLimit)console.error('Published site exceeds the 1 GB Pages limit.');
  process.exitCode=1;
}
