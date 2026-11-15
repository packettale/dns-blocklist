export const dayMilliseconds=24*60*60*1000;
export function nextDailyCheck(previous,now=Date.now()){
  if(previous?.nextCheckAt){const due=Date.parse(previous.nextCheckAt);if(Number.isFinite(due))return due;}
  const last=Date.parse(previous?.lastCheckAt||previous?.lastAttemptAt||'');
  return Number.isFinite(last)?last+dayMilliseconds:now;
}
export function reserveDailyCheck(now=Date.now()){
  return {lastCheckAt:new Date(now).toISOString(),nextCheckAt:new Date(now+dayMilliseconds).toISOString()};
}
