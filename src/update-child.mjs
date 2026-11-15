import {resolve} from 'node:path';
import {run} from './update.mjs';
import {join} from 'node:path';
import {writeJson} from './io.mjs';
const outputDir=resolve(process.argv[2]||'');
if(!process.argv[2])throw Error('Missing staging directory');
try{const manifest=await run({root:process.cwd(),outputDir,baselineDir:process.argv[3]||undefined});await writeJson(process.argv[4]||join(process.cwd(),'.cache','update-result.json'),{target:outputDir,outcome:manifest._unchanged?'unchanged':'built',inputFingerprint:manifest.inputFingerprint});}
catch(error){console.error('Update subprocess failed: '+error.message);process.exitCode=1;}
