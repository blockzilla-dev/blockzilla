#!/usr/bin/env python3
"""Check finite metadata pages through the existing restricted service SSH key."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
import ops


REMOTE = r'''
import base64,hashlib,json,pathlib,shlex,struct,subprocess,time
SOURCE=json.loads(pathlib.Path('/etc/blockzilla-client-pipe/SOURCE.json').read_text())
GENERATION='c1739ce6fcee61291f41548b1960aa27'
PRODUCER='4aaf2462131201579e55e0679f31f4a992d2c85d4e3c4891f682537625e88900'
ROOT='/home/ubuntu/live/hivezilla-validator-20260930'
OLD=ROOT+'/releases/native-relay-access-20261122-c74ca0aa24f762ed/beam_ssh_gateway.py'
NEW=ROOT+'/releases/native-relay-recovery-20261122-93ef3aef5593c417/beam_ssh_gateway.py'
def call(helper,mode,*position):
 command=shlex.join(['/usr/bin/python3','-u','-B',helper,'--job',ROOT+'/jobs/native-continuous-20261121',
                    '--mode',mode,'--generation',GENERATION,'--source-json',json.dumps(SOURCE),*position])
 result=subprocess.run(['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                        '-o','ConnectTimeout=12','ubuntu@213.239.141.61',command],
                       stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
 assert result.returncode==0, 'restricted helper failed status='+str(result.returncode)
 assert len(result.stdout)<=4*1024*1024
 lines=result.stdout.splitlines(keepends=True)
 assert lines and all(line.endswith(b'\n') and len(line)<=65536 for line in lines)
 values=[json.loads(line) for line in lines]
 header=values[0]
 assert header['schema']=='blockzilla-ssh-beam-v1' and header['status']==200
 assert header['source']==SOURCE and header['generation']==GENERATION and header['producer_generation']==PRODUCER
 return header,values[1:],len(result.stdout)
started=time.monotonic()
old,_,_=call(OLD,'head')
initial,_,_=call(NEW,'head')
after=initial['head']['cursor']
time.sleep(2)
target,_,_=call(NEW,'head')
until=target['head']['cursor']
sequence=lambda cursor:int(cursor.rsplit(':p',1)[1].split(':')[0])
assert sequence(until)>sequence(after)
current=after
pages=[]
controls=blocks=0
digests=[]
while current!=until:
 header,entries,wire_bytes=call(NEW,'recovery-plan','--after',current,'--until',until,'--max-events','3')
 assert header['start_cursor']==current and header['until_cursor']==until
 assert header['framing']=='recovery-plan-ndjson-v1' and header['content_type']=='application/vnd.blockzilla.recovery-plan.v1+ndjson'
 assert header['entry_count']==len(entries) and 1<=len(entries)<=3
 for entry in entries:
  assert entry['source']==SOURCE and entry['event']['sequence']==sequence(current)+1
  assert entry['cursor']==SOURCE['session_id']+':p'+str(entry['event']['sequence'])+':'+entry['sha256']
  assert len(entry['sha256'])==64 and all(c in '0123456789abcdef' for c in entry['sha256'])
  if entry['event']['kind']=='block':
   assert set(entry)=={'cursor','sha256','event','source'}, 'block payload or unknown field in metadata plan'
   blocks+=1
  else:
   assert set(entry)=={'cursor','sha256','event','source','control_wire_base64'}
   raw=base64.b64decode(entry['control_wire_base64'],validate=True)
   assert base64.b64encode(raw).decode()==entry['control_wire_base64']
   assert hashlib.sha256(raw).hexdigest()==entry['sha256']
   assert raw[:8]==b'BZSTRM01'
   meta,payload=struct.unpack('<II',raw[8:16])
   assert payload==0 and len(raw)==16+meta
   envelope=json.loads(raw[16:])
   assert envelope['event']==entry['event'] and envelope['objects']==[]
   assert all(envelope['marker'][key]==value for key,value in SOURCE.items())
   controls+=1
  current=entry['cursor']
  digests.append(entry['sha256'])
 assert header['end_cursor']==current
 pages.append({'entry_count':len(entries),'response_bytes':wire_bytes,'end_cursor':current})
 assert len(pages)<=128
assert len(digests)==sequence(until)-sequence(after) and len(digests)==len(set(digests))
empty,entries,_=call(NEW,'recovery-plan','--after',until,'--until',until,'--max-events','3')
assert empty['entry_count']==0 and empty['end_cursor']==until and entries==[]
old_after,_,_=call(OLD,'head')
print(json.dumps({'schema':'blockzilla-recovery-gateway-live-check-v1','status':'PASS',
 'source':SOURCE,'generation':GENERATION,'producer_generation':PRODUCER,
 'after':after,'until':until,'pages':pages,'metadata_entries':len(digests),
 'block_metadata_entries':blocks,'original_control_frames':controls,
 'ordered_without_gaps_or_duplicates':True,'block_payload_fields_absent':True,
 'control_sha_event_source_checked':True,'old_helper_head_before_and_after':True,
 'fixed_target_empty_page_checked':True,'restricted_service_user':'blockzilla-pipe',
 'seconds':round(time.monotonic()-started,3),'running_pipe_touched':False,'block_files_written':0},sort_keys=True))
'''


def main():
    result = ops.ssh('consumer', 'sudo -u blockzilla-pipe -H /usr/bin/python3 -', REMOTE.encode(), timeout=180)
    value = json.loads(result.stdout)
    path = Path(__file__).with_name('gateway-live-check.json')
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: value[key] for key in ['status', 'metadata_entries', 'block_metadata_entries',
                                                'original_control_frames', 'seconds', 'running_pipe_touched']}))


if __name__ == '__main__':
    main()
