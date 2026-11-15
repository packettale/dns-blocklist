import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizedKind} from '../src/validate.mjs';
test('streaming validator recognizes canonical ASCII domains and global IPs without accepting malformed entries',()=>{
  for(const host of ['ads.site.com','xn--bcher-kva.de','0-valid.co.uk',`${'a'.repeat(63)}.com`,'example.onion'])assert.equal(normalizedKind(host),'domains',host);
  for(const ip of ['8.8.8.8','2606:4700:4700::1111'])assert.equal(normalizedKind(ip),'ips',ip);
  for(const value of ['','ADS.COM','ads.com.','bücher.de','xn--.com','0.0.0.0','127.0.0.1','10.1.2.3','8.8.8.0/24','2001:db8::1','2606:4700:4700:0:0:0:0:1111','0.0.0.0 ads.com','ads.com\r','-ads.com','ads-.com','ads..com','a.123','foo.local','foo.arpa','foo.example',`${'a'.repeat(64)}.com`])assert.equal(normalizedKind(value),null,value);
});
