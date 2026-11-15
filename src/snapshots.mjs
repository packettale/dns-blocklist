import {readFile,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {writeJson,jsonFile} from './io.mjs';

export class SnapshotStore {
  constructor({root,validate}){
    this.root=root;this.validate=validate;
    this.slots=['a','b'];this.activeSlot=null;
    this.pointer=join(root,'.cache','snapshots','active.json');
    this.active={directory:join(root,'dist'),manifest:null};
  }
  directory(slot){if(!this.slots.includes(slot))throw Error('Invalid snapshot slot');return join(this.root,'.cache','snapshots',slot);}
  async initialize(){
    const pointer=await jsonFile(this.pointer);
    if(pointer&&!this.slots.includes(pointer.slot))throw Error('Invalid active snapshot pointer');
    const candidates=pointer?[{directory:this.directory(pointer.slot),slot:pointer.slot},{directory:join(this.root,'dist'),slot:null}]:[{directory:join(this.root,'dist'),slot:null}];
    for(const candidate of candidates){
      try{
        const manifest=JSON.parse(await readFile(join(candidate.directory,'stats.json'),'utf8'));
        await this.validate(candidate.directory);
        this.active={directory:candidate.directory,manifest};this.activeSlot=candidate.slot;return this.active;
      }catch(error){if(error.code!=='ENOENT')throw error;}
    }
    return this.active;
  }
  async target(){const slot=this.activeSlot==='a'?'b':'a',directory=this.directory(slot);await mkdir(directory,{recursive:true});return {slot,directory};}
  async commit({slot,directory},manifest){
    if(slot===this.activeSlot||directory!==this.directory(slot))throw Error('Cannot overwrite the active snapshot');
    if(manifest.inputFingerprint===this.active.manifest?.inputFingerprint)return false;
    await this.validate(directory);
    await writeJson(this.pointer,{slot,publishedAt:manifest.publishedAt,inputFingerprint:manifest.inputFingerprint});
    this.active={directory,manifest};this.activeSlot=slot;return true;
  }
}
