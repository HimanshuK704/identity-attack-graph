"""Generate deterministic synthetic Identity Attack Graph data for demos/tests.
All people, accounts, devices, and transactions are fictional.
"""
from __future__ import annotations
import argparse, json, random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = 7042026
BASE_TIME = datetime(2026, 10, 24, 4, 0, tzinfo=timezone.utc)


def iso(dt): return dt.isoformat().replace('+00:00', 'Z')

def generate(seed: int = SEED):
    rng = random.Random(seed)
    entities, events, relationships, scenarios = [], [], [], []
    entity_by_id = {}
    def add_entity(eid, etype, label, scenario_id, ground_truth, **metadata):
        obj = {'id': eid, 'type': etype, 'label': label, 'scenario_id': scenario_id,
               'ground_truth_label': ground_truth, 'metadata': metadata}
        entities.append(obj); entity_by_id[eid] = obj
        return eid
    def add_event(eid, event_type, source, target, minutes, scenario_id, ground_truth, **details):
        timestamp = iso(BASE_TIME + timedelta(minutes=minutes))
        events.append({'id': eid, 'event_type': event_type, 'timestamp': timestamp,
                       'source_id': source, 'target_id': target, 'scenario_id': scenario_id,
                       'ground_truth_label': ground_truth, 'details': details})
        relationships.append({'id': f'REL-{len(relationships)+1:04d}', 'source': source,
                              'target': target, 'type': event_type, 'timestamp': timestamp,
                              'evidence_id': eid, 'scenario_id': scenario_id})
    def scenario(sid, name, label, description):
        scenarios.append({'id': sid, 'name': name, 'ground_truth_label': label,
                          'description': description, 'synthetic': True})

    scenario('SCN-01','Ordinary legitimate activity','BENIGN','Routine account access and occasional transfers.')
    scenario('SCN-02','Benign shared public infrastructure','BENIGN','Several legitimate accounts use one public IP; sharing alone should not trigger high risk.')
    scenario('SCN-03','Shared device with additional suspicious context','PLANTED_SUSPICIOUS','Multiple accounts share a device and show tightly timed access and transfers.')
    scenario('SCN-04','Common beneficiary concentration','PLANTED_SUSPICIOUS','Multiple accounts transfer to a common synthetic beneficiary in a short interval.')
    scenario('SCN-05','Rapid coordinated activity','PLANTED_SUSPICIOUS','A set of accounts generate closely timed sessions and transfers.')
    scenario('SCN-06','Ambiguous mixed infrastructure','AMBIGUOUS','Shared network signal plus otherwise mixed activity; requires human review.')
    scenario('SCN-07','Impersonation-linked account takeover','PLANTED_SUSPICIOUS','An established account shows unfamiliar access followed by transfers to a new beneficiary. This is an investigation lead, not proof of impersonation.')

    # Ordinary benign entities/events
    for i in range(1, 31):
        sid='SCN-01'; acc=f'ACC-{i:03d}'; dev=f'DEV-{i:03d}'; ip=f'IP-{i:03d}'; ben=f'BEN-{i:03d}'
        add_entity(acc,'ACCOUNT',f'Account {i:03d}',sid,'BENIGN',segment='retail')
        add_entity(dev,'DEVICE',f'Device {i:03d}',sid,'BENIGN',device_family=rng.choice(['mobile','desktop','tablet']))
        add_entity(ip,'IP_ADDRESS',f'Synthetic IP {i:03d}',sid,'BENIGN',network_type='residential')
        add_entity(ben,'BENEFICIARY',f'Beneficiary {i:03d}',sid,'BENIGN',kind='personal')
        add_entity(f'SES-{i:03d}','SESSION',f'Session {i:03d}',sid,'BENIGN',status='completed')
        add_entity(f'PH-{i:03d}','PHONE',f'Synthetic phone {i:03d}',sid,'BENIGN')
        add_entity(f'EM-{i:03d}','EMAIL',f'user{i:03d}@example.test',sid,'BENIGN')
        add_event(f'EV-{len(events)+1:04d}','USES_DEVICE',acc,dev,i*13,sid,'BENIGN')
        add_event(f'EV-{len(events)+1:04d}','LOGGED_IN_FROM',acc,ip,i*13+1,sid,'BENIGN')
        add_event(f'EV-{len(events)+1:04d}','HAS_SESSION',acc,f'SES-{i:03d}',i*13+2,sid,'BENIGN')
        add_event(f'EV-{len(events)+1:04d}','OWNS_PHONE',acc,f'PH-{i:03d}',i*13+3,sid,'BENIGN')
        add_event(f'EV-{len(events)+1:04d}','OWNS_EMAIL',acc,f'EM-{i:03d}',i*13+4,sid,'BENIGN')
        add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,ben,i*13+5,sid,'BENIGN',amount=round(rng.uniform(8,220),2),currency='USD')

    # Benign shared IP: do not add a shared-device signal or suspicious timing
    sid='SCN-02'; shared_ip=add_entity('IP-SHARED-01','IP_ADDRESS','Campus public IP',sid,'BENIGN',network_type='campus_nat')
    for i in range(31, 41):
        acc=f'ACC-{i:03d}'; dev=f'DEV-{i:03d}'; ben=f'BEN-{i:03d}'
        add_entity(acc,'ACCOUNT',f'Account {i:03d}',sid,'BENIGN',segment='student')
        add_entity(dev,'DEVICE',f'Device {i:03d}',sid,'BENIGN',device_family='mobile')
        add_entity(ben,'BENEFICIARY',f'Beneficiary {i:03d}',sid,'BENIGN',kind='personal')
        add_event(f'EV-{len(events)+1:04d}','USES_DEVICE',acc,dev,500+i*17,sid,'BENIGN')
        add_event(f'EV-{len(events)+1:04d}','LOGGED_IN_FROM',acc,shared_ip,500+i*17+2,sid,'BENIGN')
        add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,ben,500+i*17+20,sid,'BENIGN',amount=round(rng.uniform(10,90),2),currency='USD')

    # Suspicious shared device and rapid activity
    sid='SCN-03'; common_dev=add_entity('DEV-ATTACK-01','DEVICE','Shared synthetic device',sid,'PLANTED_SUSPICIOUS',device_family='emulated_mobile')
    attack_ip=add_entity('IP-ATTACK-01','IP_ADDRESS','Synthetic hosting IP',sid,'PLANTED_SUSPICIOUS',network_type='hosting')
    for i in range(41, 49):
        acc=f'ACC-{i:03d}'; ses=f'SES-{i:03d}'; ben=f'BEN-{i:03d}'
        add_entity(acc,'ACCOUNT',f'Account {i:03d}',sid,'PLANTED_SUSPICIOUS',segment='retail')
        add_entity(ses,'SESSION',f'Session {i:03d}',sid,'PLANTED_SUSPICIOUS',status='completed')
        add_entity(ben,'BENEFICIARY',f'Beneficiary {i:03d}',sid,'PLANTED_SUSPICIOUS',kind='new_payee')
        t=1000+i-41
        add_event(f'EV-{len(events)+1:04d}','USES_DEVICE',acc,common_dev,t,sid,'PLANTED_SUSPICIOUS')
        add_event(f'EV-{len(events)+1:04d}','LOGGED_IN_FROM',acc,attack_ip,t+1,sid,'PLANTED_SUSPICIOUS')
        add_event(f'EV-{len(events)+1:04d}','HAS_SESSION',acc,ses,t+2,sid,'PLANTED_SUSPICIOUS')
        add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,ben,t+3,sid,'PLANTED_SUSPICIOUS',amount=round(rng.uniform(700,1600),2),currency='USD')

    # Common beneficiary: eight accounts to one beneficiary
    sid='SCN-04'; mule=add_entity('BEN-COMMON-01','BENEFICIARY','Common synthetic beneficiary',sid,'PLANTED_SUSPICIOUS',kind='high_concentration_demo')
    for i in range(49, 57):
        acc=f'ACC-{i:03d}'; ip=f'IP-{i:03d}'
        add_entity(acc,'ACCOUNT',f'Account {i:03d}',sid,'PLANTED_SUSPICIOUS',segment='retail')
        add_entity(ip,'IP_ADDRESS',f'Synthetic IP {i:03d}',sid,'PLANTED_SUSPICIOUS',network_type='residential')
        t=1500+(i-49)*3
        add_event(f'EV-{len(events)+1:04d}','LOGGED_IN_FROM',acc,ip,t,sid,'PLANTED_SUSPICIOUS')
        add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,mule,t+1,sid,'PLANTED_SUSPICIOUS',amount=round(rng.uniform(450,1100),2),currency='USD')

    # Separate rapid coordinated activity scenario for clear demo selection
    sid='SCN-05'; rapid_ben=add_entity('BEN-RAPID-01','BENEFICIARY','Rapid-flow synthetic beneficiary',sid,'PLANTED_SUSPICIOUS',kind='new_payee')
    rapid_ip=add_entity('IP-RAPID-01','IP_ADDRESS','Synthetic rapid-activity IP',sid,'PLANTED_SUSPICIOUS',network_type='hosting')
    for i in range(65, 73):
        acc=f'ACC-{i:03d}'; ses=f'SES-{i:03d}'; dev=f'DEV-{i:03d}'
        add_entity(acc,'ACCOUNT',f'Account {i:03d}',sid,'PLANTED_SUSPICIOUS',segment='retail')
        add_entity(ses,'SESSION',f'Session {i:03d}',sid,'PLANTED_SUSPICIOUS',status='completed')
        add_entity(dev,'DEVICE',f'Device {i:03d}',sid,'PLANTED_SUSPICIOUS',device_family='emulated_mobile')
        t=1800+(i-65)*2
        add_event(f'EV-{len(events)+1:04d}','LOGGED_IN_FROM',acc,rapid_ip,t,sid,'PLANTED_SUSPICIOUS')
        add_event(f'EV-{len(events)+1:04d}','HAS_SESSION',acc,ses,t+1,sid,'PLANTED_SUSPICIOUS')
        add_event(f'EV-{len(events)+1:04d}','USES_DEVICE',acc,dev,t+2,sid,'PLANTED_SUSPICIOUS')
        add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,rapid_ben,t+3,sid,'PLANTED_SUSPICIOUS',amount=round(rng.uniform(500,1300),2),currency='USD')

    # Ambiguous shared business network, moderate ordinary transfers
    sid='SCN-06'; office_ip=add_entity('IP-OFFICE-01','IP_ADDRESS','Synthetic office NAT',sid,'AMBIGUOUS',network_type='business_nat')
    for i in range(57, 65):
        acc=f'ACC-{i:03d}'; dev=f'DEV-{i:03d}'; ben=f'BEN-{i:03d}'
        add_entity(acc,'ACCOUNT',f'Account {i:03d}',sid,'AMBIGUOUS',segment='small_business')
        add_entity(dev,'DEVICE',f'Device {i:03d}',sid,'AMBIGUOUS',device_family='desktop')
        add_entity(ben,'BENEFICIARY',f'Beneficiary {i:03d}',sid,'AMBIGUOUS',kind='business')
        t=2000+i*11
        add_event(f'EV-{len(events)+1:04d}','USES_DEVICE',acc,dev,t,sid,'AMBIGUOUS')
        add_event(f'EV-{len(events)+1:04d}','LOGGED_IN_FROM',acc,office_ip,t+1,sid,'AMBIGUOUS')
        add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,ben,t+35,sid,'AMBIGUOUS',amount=round(rng.uniform(100,500),2),currency='USD')

    # SCN-07: Impersonation-Linked Account Takeover
    sid='SCN-07'
    # Established account and known activity
    acc='ACC-073'
    known_dev=add_entity('DEV-073','DEVICE','Known device 073',sid,'BENIGN',device_family='mobile')
    known_ip=add_entity('IP-073','IP_ADDRESS','Known residential IP 073',sid,'BENIGN',network_type='residential')
    known_ses=add_entity('SES-073','SESSION','Established session 073',sid,'BENIGN')
    known_ben=add_entity('BEN-073','BENEFICIARY','Known beneficiary 073',sid,'BENIGN',kind='personal')

    add_entity(acc,'ACCOUNT','Account 073',sid,'AMBIGUOUS',segment='retail',account_tenure='established')

    t=3100
    add_event(f'EV-{len(events)+1:04d}','USES_DEVICE',acc,known_dev,t,sid,'BENIGN')
    add_event(f'EV-{len(events)+1:04d}','LOGGED_IN_FROM',acc,known_ip,t+1,sid,'BENIGN')
    add_event(f'EV-{len(events)+1:04d}','HAS_SESSION',acc,known_ses,t+2,sid,'BENIGN')
    add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,known_ben,t+10,sid,'BENIGN',amount=120.00,currency='USD')

    # Unfamiliar access context
    new_dev=add_entity('DEV-TAKEOVER-01','DEVICE','Unfamiliar device',sid,'PLANTED_SUSPICIOUS',device_family='unrecognized_mobile')
    new_ip=add_entity('IP-TAKEOVER-01','IP_ADDRESS','Unfamiliar IP',sid,'PLANTED_SUSPICIOUS',network_type='hosting')
    new_ses=add_entity('SES-TAKEOVER-01','SESSION','Unfamiliar session',sid,'PLANTED_SUSPICIOUS')
    new_ben=add_entity('BEN-TAKEOVER-01','BENEFICIARY','New beneficiary',sid,'PLANTED_SUSPICIOUS',kind='new_payee')

    add_event(f'EV-{len(events)+1:04d}','USES_DEVICE',acc,new_dev,t+40,sid,'PLANTED_SUSPICIOUS')
    add_event(f'EV-{len(events)+1:04d}','LOGGED_IN_FROM',acc,new_ip,t+41,sid,'PLANTED_SUSPICIOUS')
    add_event(f'EV-{len(events)+1:04d}','HAS_SESSION',acc,new_ses,t+42,sid,'PLANTED_SUSPICIOUS')
    add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,new_ben,t+50,sid,'PLANTED_SUSPICIOUS',amount=920.00,currency='USD')
    add_event(f'EV-{len(events)+1:04d}','INITIATED_TRANSACTION',acc,new_ben,t+60,sid,'PLANTED_SUSPICIOUS',amount=780.00,currency='USD')
   
    # Ensure transaction nodes exist for transaction events
    tx_events=[e for e in events if e['event_type']=='INITIATED_TRANSACTION']
    for idx,e in enumerate(tx_events,1):
        tid=f'TXN-{idx:04d}'
        add_entity(tid,'TRANSACTION',f'Transaction {idx:04d}',e['scenario_id'],e['ground_truth_label'],amount=e['details']['amount'],currency=e['details']['currency'],timestamp=e['timestamp'])
        # Link account to transaction node and transaction node to beneficiary; retain original event as provenance
        original_target=e['target_id']; original_source=e['source_id']
        e['target_id']=tid
        # update corresponding relationship target to transaction
        for rel in relationships:
            if rel['evidence_id']==e['id']:
                rel['target']=tid
                break
        relationships.append({'id':f'REL-{len(relationships)+1:04d}','source':tid,'target':original_target,'type':'SENT_TO','timestamp':e['timestamp'],'evidence_id':e['id'],'scenario_id':e['scenario_id']})

    return {'metadata': {'project':'Identity Attack Graph','synthetic_only':True,'seed':seed,'generated_at':'deterministic-demo-time','base_time':iso(BASE_TIME)},
            'entities':entities,'events':events,'relationships':relationships,'scenarios':scenarios}


def summarize(data):
    return {'entity_count':len(data['entities']),'event_count':len(data['events']),
            'relationship_count':len(data['relationships']),
            'entity_counts_by_type':dict(sorted(Counter(e['type'] for e in data['entities']).items())),
            'event_counts_by_type':dict(sorted(Counter(e['event_type'] for e in data['events']).items())),
            'scenario_counts':dict(sorted(Counter(e['scenario_id'] for e in data['events']).items())),
            'ground_truth_counts':dict(sorted(Counter(e['ground_truth_label'] for e in data['events']).items()))}

def validate(data):
    assert len(data['entities']) >= 100, f"Need >=100 entities, got {len(data['entities'])}"
    assert len(data['events']) >= 300, f"Need >=300 events, got {len(data['events'])}"
    assert len(data['relationships']) >= 300, f"Need >=300 relationships, got {len(data['relationships'])}"
    eids=[e['id'] for e in data['entities']]; vids=[e['id'] for e in data['events']]; rids=[r['id'] for r in data['relationships']]
    assert len(eids)==len(set(eids)), 'Duplicate entity IDs'
    assert len(vids)==len(set(vids)), 'Duplicate event IDs'
    assert len(rids)==len(set(rids)), 'Duplicate relationship IDs'
    known=set(eids)
    for ev in data['events']:
        assert ev['source_id'] in known and ev['target_id'] in known, f"Invalid event endpoint: {ev['id']}"
        datetime.fromisoformat(ev['timestamp'].replace('Z','+00:00'))
        assert ev['ground_truth_label'] in {'BENIGN','PLANTED_SUSPICIOUS','AMBIGUOUS'}
    for rel in data['relationships']:
        assert rel['source'] in known and rel['target'] in known, f"Invalid relationship endpoint: {rel['id']}"
        datetime.fromisoformat(rel['timestamp'].replace('Z','+00:00'))
    labels={s['ground_truth_label'] for s in data['scenarios']}
    assert {'BENIGN','PLANTED_SUSPICIOUS','AMBIGUOUS'} <= labels
    return summarize(data)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--out',default=str(ROOT/'data')); parser.add_argument('--seed',type=int,default=SEED); args=parser.parse_args()
    out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    data=generate(args.seed); summary=validate(data)
    for key in ['entities','events','relationships','scenarios']:
        (out/f'{key}.json').write_text(json.dumps(data[key],indent=2)+'\n',encoding='utf-8')
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2)); print(f'\nDataset written to: {out.resolve()}')
if __name__=='__main__': main()
