//! Bounded replay closure from either consumer custody or the local feed tip.
use crate::{journal::atomic_json, processed::{ContinuousLiveOptions, ProcessedReleaseCheckpoint,
    ProcessedReleasedBank, ProcessedReleasedSlotControl, PROCESSED_RELEASE_SCHEMA, processed_release_digest}};
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::{self as v2, SourceIdentity, chain::Chain};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::{collections::BTreeSet, fs, io::Read, path::{Path, PathBuf}};

pub struct Retention {
    pub policy: ContinuousLiveOptions,
    pub generation: String,
    pub source: SourceIdentity,
    pub output: PathBuf,
    pub processed: PathBuf,
    pub local_beam: bool,
}
pub fn tables(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS input_commits(processed_sequence INTEGER PRIMARY KEY,last_event_sequence INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS input_commit_event ON input_commits(last_event_sequence,processed_sequence);
      CREATE TABLE IF NOT EXISTS feed_retention(id INTEGER PRIMARY KEY CHECK(id=1),base_sequence INTEGER NOT NULL,base_sha256 TEXT NOT NULL,gap_base_sequence INTEGER NOT NULL,latest_gap_sequence INTEGER NOT NULL,next_release_id INTEGER NOT NULL);
      INSERT OR IGNORE INTO feed_retention VALUES(1,0,'-',0,0,1);
      CREATE TABLE IF NOT EXISTS coverage_gaps(sequence INTEGER PRIMARY KEY,processed_sequence INTEGER NOT NULL UNIQUE,gap_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS release_jobs(id INTEGER PRIMARY KEY,checkpoint TEXT NOT NULL,sha256 TEXT NOT NULL,completed INTEGER NOT NULL DEFAULT 0);")?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS retention_authority(id INTEGER PRIMARY KEY CHECK(id=1),json TEXT NOT NULL,previous_json TEXT);
        CREATE TABLE IF NOT EXISTS local_gap_history(sequence INTEGER PRIMARY KEY,gap_json TEXT NOT NULL CHECK(length(gap_json)<=65536));")?;
    let has_column:bool={let mut q=db.prepare("PRAGMA table_info(banks)")?;q.query_map([],|r|r.get::<_,String>(1))?.collect::<rusqlite::Result<Vec<_>>>()?.iter().any(|v|v=="last_processed_event")};
    if !has_column {db.execute_batch("ALTER TABLE banks ADD COLUMN last_processed_event INTEGER NOT NULL DEFAULT 0;")?;}
    Ok(())
}
pub fn record_input(db: &mut Connection, sequence: u64, bank:Option<(u64,u64)>) -> Result<()> {
    let tx=db.transaction()?;
    let event: u64=tx.query_row("SELECT event_sequence FROM feed_state WHERE id=1",[],|r|r.get(0))?;
    tx.execute("INSERT INTO input_commits VALUES(?1,?2) ON CONFLICT(processed_sequence) DO UPDATE SET last_event_sequence=max(last_event_sequence,excluded.last_event_sequence)",params![sequence,event])?;
    tx.execute("UPDATE feed_state SET processed_sequence=?1 WHERE id=1",[sequence])?;
    if let Some((slot,bank))=bank {tx.execute("UPDATE banks SET last_processed_event=max(last_processed_event,?3) WHERE slot=?1 AND bank=?2",params![slot,bank,sequence])?;}
    tx.commit()?;Ok(())
}
pub fn record_gap(db: &mut Connection, sequence:u64, generation:&str, raw:&Value) -> Result<()> {
    let gap=raw.get("gap").context("missing coverage gap")?;
    let n=|key|gap[key].as_u64().with_context(||format!("missing gap {key}"));
    let complete=gap["complete_bank"].as_bool().context("gap lacks complete Bank flag")?;
    let slot_only=gap["schema"]=="hivezilla-slot-control-gap-v1";
    ensure!((!complete&&(gap["schema"]=="hivezilla-incomplete-bank-gap-v1" || slot_only&&gap["bank_id"].is_null()) || complete&&gap["schema"]=="hivezilla-nonterminal-bank-gap-v1"&&gap["canonical_status"]=="UNKNOWN"&&gap["reason"]=="complete-unconfirmed-bank-expired")
        && gap["producer_generation"]==generation && n("gap_sequence")?==sequence
        && n("slot")?<=v2::SAFE && (slot_only || n("bank_id")?<=v2::SAFE)
        && n("first_source_sequence")?>0 && n("last_source_sequence")?>=n("first_source_sequence")?
        && v2::is_digest(gap["evidence_sha256"].as_str().unwrap_or(""))
        && gap["captured_input_preserved"]==true,
        "invalid Bank coverage gap");
    let encoded=serde_json::to_string(gap)?;
    let tx=db.transaction()?;
    if complete {
        let(path,event,state):(String,String,String)=tx.query_row("SELECT artifact,payload_event,state FROM banks WHERE slot=?1 AND bank=?2",params![n("slot")?,n("bank_id")?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let event:v2::BankEvent=serde_json::from_str(&event)?;
        ensure!(gap["bank_identity"]==serde_json::to_value(&event.bank)?&&gap["custody"]["artifact"]==path&&gap["custody"]["marker_sha256"]==event.payload_sha256&&matches!(state.as_str(),"published"|"expired"),"complete gap Bank custody differs");
        tx.execute("UPDATE banks SET state='expired',last_processed_event=?3 WHERE slot=?1 AND bank=?2",params![n("slot")?,n("bank_id")?,sequence])?;
    }
    let old:Option<String>=tx.query_row("SELECT gap_json FROM coverage_gaps WHERE sequence=?1",[sequence],|r|r.get(0)).optional()?;
    if let Some(old)=old {ensure!(old==encoded,"coverage gap changed");}
    else {tx.execute("INSERT INTO coverage_gaps VALUES(?1,?1,?2)",params![sequence,encoded])?;}
    tx.execute("UPDATE feed_retention SET latest_gap_sequence=max(latest_gap_sequence,?1) WHERE id=1",[sequence])?;
    let event:u64=tx.query_row("SELECT event_sequence FROM feed_state WHERE id=1",[],|r|r.get(0))?;
    tx.execute("INSERT OR IGNORE INTO input_commits VALUES(?1,?2)",params![sequence,event])?;
    tx.execute("UPDATE feed_state SET processed_sequence=?1 WHERE id=1",[sequence])?;
    tx.commit()?;Ok(())
}

impl Retention {
    pub fn open(header:&Value, source:SourceIdentity, processed:&Path, output:&Path) -> Result<Option<Self>> {
        if header["producer_role"] != crate::processed::CONTINUOUS_ROLE {return Ok(None);}
        let policy:ContinuousLiveOptions=serde_json::from_value(header["continuous"].clone())?;
        policy.validate()?;
        let generation=header["producer_generation"].as_str().context("missing producer generation")?.to_owned();
        ensure!(v2::is_digest(&generation),"invalid producer generation");
        ensure!(policy.release_checkpoint==output.join("PROCESSED-RELEASE.json"),"release checkpoint differs from confirmed output");
        Ok(Some(Self{policy,generation,source,output:output.to_path_buf(),processed:processed.to_path_buf(),local_beam:false}))
    }
    pub fn authority(&self) -> Value {
        serde_json::json!({"schema":"blockzilla-retention-authority-v1",
            "mode":if self.local_beam {"local-beam-v1"} else {"consumer-ack-v1"},
            "source":self.source,"producer_generation":self.generation,
            "consumer_ack_required":!self.local_beam,
            "frontier":if self.local_beam {"full-committed-native-feed-tip"} else {"configured-consumer-ack"},
            "limits":{"retained_banks":self.policy.retained_banks,"max_retained_banks":self.policy.max_retained_banks,
                "min_retention_ms":self.policy.min_retention_ms,"max_output_bytes":self.policy.max_output_bytes}})
    }
    /// An explicit one-way policy transition. The processed source header and
    /// source-custody pins do not change. The legacy release channel is not a
    /// consumer receipt; this FULL row states who authorizes window retirement.
    pub fn bind_authority(&self, db:&mut Connection) -> Result<()> {
        let wanted=self.authority(); let encoded=serde_json::to_string(&wanted)?;
        let old:Option<(String,Option<String>)>=db.query_row("SELECT json,previous_json FROM retention_authority WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((raw,_))=&old {
            let prior:Value=serde_json::from_str(raw)?;
            if prior!=wanted {
                ensure!(self.local_beam && prior["mode"]=="consumer-ack-v1"
                    && prior["schema"]==wanted["schema"] && prior["source"]==wanted["source"]
                    && prior["producer_generation"]==wanted["producer_generation"] && prior["limits"]==wanted["limits"],
                    "retention authority changed or downgrade requested");
            }
        }
        let path=self.output.join("RETENTION-AUTHORITY.json");
        if path.try_exists()? {
            let current:Value=serde_json::from_slice(&v2::artifact::bounded_file(&path,65536)?)?;
            let known=old.as_ref().is_some_and(|(raw,previous)|
                serde_json::from_str::<Value>(raw).ok().as_ref()==Some(&current)
                || previous.as_ref().and_then(|v|serde_json::from_str::<Value>(v).ok()).as_ref()==Some(&current));
            ensure!(current==wanted || known,"unknown retention authority descriptor");
        }
        if old.as_ref().is_none_or(|(raw,_)|raw!=&encoded) {
            let tx=db.transaction()?;
            tx.execute("INSERT INTO retention_authority VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET json=excluded.json,previous_json=excluded.previous_json",
                params![encoded,old.as_ref().map(|(raw,_)|raw)])?;
            tx.commit()?;
        }
        atomic_json(&path,&wanted)?;
        Ok(())
    }
    fn frontier(&self, db:&Connection) -> Result<Option<(String,u64,u64)>> {
        if !self.local_beam {return self.acknowledged();}
        // These rows are already FULL committed by this coordinator. A reader
        // cannot hold this bounded window open by withholding an ACK.
        let n:u64=db.query_row("SELECT event_sequence FROM feed_state WHERE id=1",[],|r|r.get(0))?;
        let gap:u64=db.query_row("SELECT latest_gap_sequence FROM feed_retention WHERE id=1",[],|r|r.get(0))?;
        if n==0 {return Ok(Some((v2::cursor(&self.source.session_id,0,"-"),0,gap)));}
        let sha:Option<String>=db.query_row("SELECT frame_sha256 FROM feed_events WHERE sequence=?1",[n],|r|r.get(0)).optional()?;
        let sha=if let Some(sha)=sha {sha} else {
            let (base,sha):(u64,String)=db.query_row("SELECT base_sequence,base_sha256 FROM feed_retention WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
            ensure!(base==n,"local feed tip is missing above its replay floor");sha
        };
        ensure!(v2::is_digest(&sha),"invalid local feed tip hash");
        Ok(Some((v2::cursor(&self.source.session_id,n,&sha),n,gap)))
    }
    fn acknowledged(&self) -> Result<Option<(String,u64,u64)>> {
        let path=self.output.join("consumer-acks.sqlite");
        if !path.exists(){return Ok(None);}
        ensure!(fs::symlink_metadata(&path)?.file_type().is_file(),"unsafe consumer ACK database");
        let db=crate::journal::open_reader(&path)?;
        let ready:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='ack_binding')",[],|r|r.get(0))?;
        if !ready {return Ok(None);}
        let binding:Option<String>=db.query_row("SELECT json FROM ack_binding WHERE id=1",[],|r|r.get(0)).optional()?;
        let Some(binding)=binding else{return Ok(None);};
        let binding:Value=serde_json::from_str(&binding)?;
        ensure!(binding["schema"]=="blockzilla-consumer-ack-config-v1","unsupported ACK binding");
        ensure!(serde_json::from_value::<SourceIdentity>(binding["source"].clone())?==self.source
            && binding["consumers"].as_array().context("missing required consumers")?.iter().any(|c|c==&self.policy.required_consumer),"ACK source/consumer differs");
        let row:Option<(String,u64,u64)>=db.query_row("SELECT cursor,sequence,gap_sequence FROM consumer_acks WHERE consumer_id=?1",[&self.policy.required_consumer],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((cursor,n,_))=&row {
            let(s,actual,_)=v2::parse_cursor(cursor)?;
            ensure!(s==self.source.session_id && actual==*n,"ACK cursor differs");
        }
        let Some((cursor,mut n,mut gap))=row else{return Ok(None);};
        for id in binding["consumers"].as_array().unwrap() {
            let id=id.as_str().context("invalid ACK consumer")?;
            let other:Option<(u64,u64)>=db.query_row("SELECT sequence,gap_sequence FROM consumer_acks WHERE consumer_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            let Some((other_n,other_gap))=other else{return Ok(None);};
            n=n.min(other_n);gap=gap.min(other_gap);
        }
        Ok(Some((cursor,n,gap)))
    }
    fn pending(&self,db:&mut Connection) -> Result<bool> {
        let row:Option<(u64,String,String)>=db.query_row("SELECT id,checkpoint,sha256 FROM release_jobs WHERE completed=0 ORDER BY id LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((id,raw,sha))=row else{return Ok(false);};
        let checkpoint:ProcessedReleaseCheckpoint=serde_json::from_str(&raw)?;
        ensure!(processed_release_digest(&checkpoint)?==sha,"saved release changed");
        let receipt=self.processed.join(format!("retention/release-{id}.json"));
        if receipt.exists(){
            ensure!(fs::symlink_metadata(&receipt)?.file_type().is_file(),"unsafe release receipt");
            let mut bytes=Vec::new();fs::File::open(&receipt)?.take(1024*1024+1).read_to_end(&mut bytes)?;
            ensure!(bytes.len()<=1024*1024,"release receipt exceeds bound");
            let r:Value=serde_json::from_slice(&bytes)?;
            ensure!(r["schema"]=="hivezilla-processed-release-receipt-v1" && r["state"]=="COMPLETE"
                && r["source"]==serde_json::to_value(&self.source)? && r["producer_generation"]==self.generation
                && r["consumer_id"]==self.policy.required_consumer && r["release_id"]==id && r["checkpoint_sha256"]==sha,
                "release receipt differs");
            ensure!(r["processed_through_sequence"]==checkpoint.processed_through_sequence
                && r["acknowledged_gap_sequence"]==checkpoint.acknowledged_gap_sequence
                && r["released_banks"]==checkpoint.released_banks.len()
                && r["released_slot_controls"]==checkpoint.released_slot_controls.len(),"release receipt frontier/count differs");
            let tx=db.transaction()?;
            tx.execute("UPDATE release_jobs SET completed=1 WHERE id=?1",[id])?;
            tx.execute("DELETE FROM release_jobs WHERE completed=1 AND id<?1",[id.saturating_sub(1)])?;
            tx.commit()?;
            Ok(false)
        }else{
            atomic_json(&self.policy.release_checkpoint,&checkpoint)?;
            Ok(true)
        }
    }
    /// Publish only after the v2 replay closure is durably fenced off.
    pub fn step(&self,db:&mut Connection,_input:&Connection,chain:&mut Chain) -> Result<()> {
        if self.pending(db)? {return Ok(());}
        let Some((ack_cursor,ack,gap_ack))=self.frontier(db)? else{return Ok(());};
        let processed_through:u64=db.query_row("SELECT coalesce(max(processed_sequence),0) FROM input_commits WHERE last_event_sequence<=?1",[ack],|r|r.get(0))?;
        let now=super::now();
        let floor_height:Option<u64>=db.query_row("SELECT json_extract(payload_event,'$.block_height') FROM banks WHERE state IN ('rooted','invalidated') ORDER BY json_extract(payload_event,'$.block_height') DESC LIMIT 1 OFFSET ?1",[self.policy.retained_banks],|r|r.get(0)).optional()?;
        let mut candidates=Vec::new();let mut controls=Vec::new();
        if let Some(floor)=floor_height {
            let mut q=db.prepare("SELECT b.slot,b.bank,b.artifact,b.payload_event,max(e.sequence),coalesce(min(t.published_at_unix_ms),0),b.last_processed_event FROM banks b JOIN feed_events e ON e.artifact=b.artifact LEFT JOIN publication_times t ON t.sequence=e.sequence WHERE b.state IN ('rooted','invalidated') AND json_extract(b.payload_event,'$.block_height')<=?1 GROUP BY b.slot,b.bank HAVING max(e.sequence)<=?2 ORDER BY min(e.sequence),b.slot,b.bank LIMIT 64")?;
            for row in q.query_map(params![floor,ack],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,u64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,u64>(4)?,r.get::<_,u64>(5)?,r.get::<_,u64>(6)?)))? {
                let(slot,bank,path,raw,_,published,last)=row?;
                if published==0 || now.saturating_sub(published)<self.policy.min_retention_ms {continue;}
                let event:v2::BankEvent=serde_json::from_str(&raw)?;
                if chain.latest.as_ref().is_some_and(|h|h.bank==event.bank){continue;}
                if last==0 {continue;}
                candidates.push(ProcessedReleasedBank{slot,bank_id:bank,last_processed_event:last,artifact:Some(path),marker_sha256:Some(event.payload_sha256),gap_sequence:None,evidence_sha256:None});
            }
        }
        let gaps={let mut q=db.prepare("SELECT sequence,gap_json FROM coverage_gaps WHERE sequence<=?1 ORDER BY sequence LIMIT 64")?;q.query_map([gap_ack],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?};
        for(seq,raw)in gaps {let g:Value=serde_json::from_str(&raw)?;let slot=g["slot"].as_u64().context("gap slot")?;let evidence=g["evidence_sha256"].as_str().context("gap evidence")?.to_owned();
        if g["schema"]=="hivezilla-slot-control-gap-v1"{controls.push(ProcessedReleasedSlotControl{slot,last_processed_event:seq,gap_sequence:seq,evidence_sha256:evidence});continue;}
        let complete=g["complete_bank"]==true;candidates.push(ProcessedReleasedBank{slot,bank_id:g["bank_id"].as_u64().context("gap bank")?,last_processed_event:seq,artifact:if complete {Some(g["custody"]["artifact"].as_str().context("complete gap artifact")?.into())} else {None},marker_sha256:if complete {Some(g["custody"]["marker_sha256"].as_str().context("complete gap marker")?.into())} else {None},gap_sequence:Some(seq),evidence_sha256:Some(evidence)});}
        candidates.retain(|b|!chain.latest.as_ref().is_some_and(|h|h.bank.key()==(b.slot,b.bank_id)));
        // Coverage and native-frame ACKs are independent. An acknowledged gap
        // waits here until its preceding native frames are also durable.
        candidates.retain(|b|b.last_processed_event<=processed_through);
        controls.retain(|c|c.last_processed_event<=processed_through);
        candidates.truncate(self.policy.max_retained_banks as usize);
        controls.truncate((self.policy.max_retained_banks as usize).saturating_sub(candidates.len()));
        if candidates.is_empty()&&controls.is_empty(){return Ok(());}
        // Trim only a contiguous prefix: no retained event may keep a removed dependency.
        let paths:BTreeSet<_>=candidates.iter().filter_map(|b|b.artifact.clone()).collect();
        let mut prefix=Vec::new();
        {let mut q=db.prepare("SELECT sequence,artifact,frame_sha256 FROM feed_events ORDER BY sequence LIMIT 32768")?;
        for r in q.query_map([],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))? {let(n,path,sha)=r?;if n>ack||!paths.contains(&path){break;}prefix.push((n,sha));}}
        let base=prefix.last().cloned();
        let base_n=base.as_ref().map_or(0,|v|v.0);
        candidates.retain(|b|b.artifact.as_ref().is_none_or(|path|db.query_row("SELECT NOT EXISTS(SELECT 1 FROM feed_events WHERE artifact=?1 AND sequence>?2)",params![path,base_n],|r|r.get::<_,bool>(0)).unwrap_or(false)));
        // Gap IDs are sparse. Retire only their ordered prefix, so the replay
        // boundary never hides an earlier retained complete-payload gap.
        let selected_gaps:BTreeSet<_>=candidates.iter().filter_map(|b|b.gap_sequence).chain(controls.iter().map(|c|c.gap_sequence)).collect();
        let mut gap_stop=None;
        {let mut q=db.prepare("SELECT sequence FROM coverage_gaps ORDER BY sequence")?;
        for r in q.query_map([],|r|r.get::<_,u64>(0))?{let n=r?;if !selected_gaps.contains(&n){gap_stop=Some(n);break;}}}
        if let Some(stop)=gap_stop{candidates.retain(|b|b.gap_sequence.is_none_or(|n|n<stop));controls.retain(|c|c.gap_sequence<stop);}
        if candidates.is_empty()&&controls.is_empty()&&base.is_none(){return Ok(());}
        ensure!(candidates.iter().all(|b|b.last_processed_event<=processed_through)&&controls.iter().all(|c|c.last_processed_event<=processed_through),"release input frontier differs");
        let id:u64=db.query_row("SELECT next_release_id FROM feed_retention WHERE id=1",[],|r|r.get(0))?;
        let old_base:(u64,String)=db.query_row("SELECT base_sequence,base_sha256 FROM feed_retention WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let(n,sha)=base.clone().unwrap_or(old_base);
        let checkpoint=ProcessedReleaseCheckpoint{schema:PROCESSED_RELEASE_SCHEMA.into(),source:self.source.clone(),producer_generation:self.generation.clone(),consumer_id:self.policy.required_consumer.clone(),release_id:id,processed_through_sequence:processed_through,acknowledged_cursor:ack_cursor,replay_floor_cursor:v2::cursor(&self.source.session_id,n,&sha),acknowledged_gap_sequence:gap_ack,released_banks:candidates,released_slot_controls:controls};
        let mut next_chain=chain.clone();
        let keys:BTreeSet<_>=checkpoint.released_banks.iter().map(|b|format!("{}:{}",b.slot,b.bank_id)).collect();
        next_chain.banks.retain(|k,_|!keys.contains(k));
        if let Some(h)=&next_chain.latest {next_chain.can_confirm(&h.bank)?;}
        let tx=db.transaction()?;
        if self.local_beam {
            for g in checkpoint.released_banks.iter().filter_map(|b|b.gap_sequence).chain(checkpoint.released_slot_controls.iter().map(|c|c.gap_sequence)) {
                tx.execute("INSERT OR IGNORE INTO local_gap_history SELECT sequence,gap_json FROM coverage_gaps WHERE sequence=?1",[g])?;
            }
            // This is a bounded local diagnostic record, not archive custody.
            tx.execute("DELETE FROM local_gap_history WHERE sequence IN(SELECT sequence FROM local_gap_history ORDER BY sequence LIMIT max(0,(SELECT count(*) FROM local_gap_history)-?1))",[self.policy.max_retained_banks])?;
        }
        if base.is_some(){tx.execute("DELETE FROM feed_events WHERE sequence<=?1",[n])?;tx.execute("DELETE FROM publication_times WHERE sequence<=?1",[n])?;tx.execute("UPDATE feed_retention SET base_sequence=?1,base_sha256=?2 WHERE id=1",params![n,sha])?;}
        let mut gap_base=0;
        for b in &checkpoint.released_banks {
            if let Some(g)=b.gap_sequence {tx.execute("DELETE FROM coverage_gaps WHERE sequence=?1",[g])?;gap_base=gap_base.max(g);}
            if b.artifact.is_some(){tx.execute("DELETE FROM banks WHERE slot=?1 AND bank=?2",params![b.slot,b.bank_id])?;}
        }
        for c in &checkpoint.released_slot_controls {tx.execute("DELETE FROM coverage_gaps WHERE sequence=?1",[c.gap_sequence])?;gap_base=gap_base.max(c.gap_sequence);}
        tx.execute("UPDATE feed_retention SET gap_base_sequence=max(gap_base_sequence,?1),next_release_id=?2 WHERE id=1",params![gap_base,id+1])?;
        tx.execute("UPDATE feed_state SET chain_json=?1 WHERE id=1",[serde_json::to_string(&next_chain)?])?;
        tx.execute("INSERT INTO release_jobs VALUES(?1,?2,?3,0)",params![id,serde_json::to_string(&checkpoint)?,processed_release_digest(&checkpoint)?])?;
        tx.execute("DELETE FROM input_commits WHERE processed_sequence<?1",[processed_through])?;
        tx.commit()?;*chain=next_chain;
        atomic_json(&self.policy.release_checkpoint,&checkpoint)?;
        db.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct Fixture { _temp:tempfile::TempDir, retention:Retention, db:Connection, ack:Connection, chain:Chain }
    fn fixture()->Fixture {fixture_n(3)}
    fn fixture_n(count:u64)->Fixture {
        let temp=tempfile::tempdir().unwrap();let output=temp.path().join("confirmed");let processed=temp.path().join("processed");
        fs::create_dir_all(&output).unwrap();fs::create_dir_all(processed.join("retention")).unwrap();
        let source=SourceIdentity{genesis_hash:"11111111111111111111111111111111".into(),node_identity:"11111111111111111111111111111111".into(),agave_revision:"test-revision".into(),session_id:"continuous-test".into()};
        let policy=ContinuousLiveOptions{retained_banks:1,max_retained_banks:4.max(count+1),retained_events:1000,max_output_bytes:1024*1024,min_retention_ms:0,release_checkpoint:output.join("PROCESSED-RELEASE.json"),required_consumer:"sidecar-primary".into()};
        let mut db=Connection::open(output.join("feed.sqlite")).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;CREATE TABLE feed_state(id INTEGER PRIMARY KEY,processed_sequence INTEGER,event_sequence INTEGER,chain_json TEXT);INSERT INTO feed_state VALUES(1,0,0,'{}');CREATE TABLE feed_events(sequence INTEGER PRIMARY KEY,artifact TEXT,event_json TEXT,frame_sha256 TEXT);CREATE TABLE publication_times(sequence INTEGER PRIMARY KEY,published_at_unix_ms INTEGER);CREATE TABLE banks(slot INTEGER,bank INTEGER,artifact TEXT,payload_event TEXT,frame_sha256 TEXT,state TEXT,PRIMARY KEY(slot,bank));").unwrap();tables(&db).unwrap();
        for n in 1..=count {
            let e=v2::BankEvent{sequence:2*n-1,source_sequence:n,kind:"block".into(),bank:v2::BankIdentity{slot:100+n,bank_id:n,blockhash:[n as u8;32],parent_slot:99+n,parent_blockhash:[(n-1)as u8;32]},payload_sha256:format!("{n:064x}"),payload_frame_sha256:None,commitment:Some("processed".into()),confirmation_basis:Some("operator-trusted-agave-processed-bank-callback".into()),block_height:Some(n),recent_blockhash:None,observed_at_unix_ms:1,reason:None};e.validate().unwrap();
            let path=processed.join(format!("live-banks/{}-{n}.compact",100+n)).to_string_lossy().into_owned();
            db.execute("INSERT INTO banks VALUES(?1,?2,?3,?4,?5,'rooted',0)",params![100+n,n,path,serde_json::to_string(&e).unwrap(),format!("{n:064x}")]).unwrap();
            for seq in [2*n-1,2*n] {db.execute("INSERT INTO feed_events VALUES(?1,?2,?3,?4)",params![seq,path,serde_json::to_string(&e).unwrap(),format!("{seq:064x}")]).unwrap();db.execute("INSERT INTO publication_times VALUES(?1,1)",[seq]).unwrap();}
            db.execute("UPDATE feed_state SET event_sequence=?1",[2*n]).unwrap();record_input(&mut db,n,Some((100+n,n))).unwrap();
        }
        let ack=Connection::open(output.join("consumer-acks.sqlite")).unwrap();ack.execute_batch("CREATE TABLE ack_binding(id INTEGER PRIMARY KEY,json TEXT);CREATE TABLE consumer_acks(consumer_id TEXT PRIMARY KEY,sequence INTEGER,cursor TEXT,gap_sequence INTEGER);").unwrap();
        ack.execute("INSERT INTO ack_binding VALUES(1,?1)",[json!({"schema":"blockzilla-consumer-ack-config-v1","source":source,"consumers":["sidecar-primary"]}).to_string()]).unwrap();
        Fixture{_temp:temp,retention:Retention{policy,generation:"a".repeat(64),source,output,processed,local_beam:false},db,ack,chain:Chain::default()}
    }
    impl Fixture {
        fn acknowledge(&self,n:u64,gap:u64){self.ack.execute("INSERT OR REPLACE INTO consumer_acks VALUES('sidecar-primary',?1,?2,?3)",params![n,v2::cursor(&self.retention.source.session_id,n,&format!("{n:064x}")),gap]).unwrap();}
        fn step(&mut self){self.retention.step(&mut self.db,&Connection::open_in_memory().unwrap(),&mut self.chain).unwrap();}
        fn checkpoint(&self)->ProcessedReleaseCheckpoint{serde_json::from_slice(&fs::read(&self.retention.policy.release_checkpoint).unwrap()).unwrap()}
        fn receipt(&self,c:&ProcessedReleaseCheckpoint){atomic_json(&self.retention.processed.join(format!("retention/release-{}.json",c.release_id)),&json!({"schema":"hivezilla-processed-release-receipt-v1","state":"COMPLETE","source":c.source,"producer_generation":c.producer_generation,"consumer_id":c.consumer_id,"release_id":c.release_id,"checkpoint_sha256":processed_release_digest(c).unwrap(),"processed_through_sequence":c.processed_through_sequence,"acknowledged_gap_sequence":c.acknowledged_gap_sequence,"released_banks":c.released_banks.len(),"released_slot_controls":c.released_slot_controls.len()})).unwrap();}
    }
    #[test]
    fn no_ack_retains_everything_and_committed_release_resumes_after_crash(){
        let mut f=fixture();f.step();assert!(!f.retention.policy.release_checkpoint.exists());f.acknowledge(6,0);f.step();let c=f.checkpoint();
        assert_eq!(c.release_id,1);assert_eq!(c.released_banks.len(),2);assert_eq!(v2::parse_cursor(&c.replay_floor_cursor).unwrap().1,4);
        assert_eq!(f.db.query_row("SELECT count(*) FROM banks",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        fs::remove_file(&f.retention.policy.release_checkpoint).unwrap();f.step();assert_eq!(f.checkpoint(),c);
        f.receipt(&c);f.step();assert_eq!(f.db.query_row("SELECT completed FROM release_jobs WHERE id=1",[],|r|r.get::<_,u64>(0)).unwrap(),1);
    }
    #[test]
    fn later_retained_control_prevents_payload_release(){
        let mut f=fixture();f.acknowledge(6,0);let path:String=f.db.query_row("SELECT artifact FROM banks WHERE bank=1",[],|r|r.get(0)).unwrap();
        f.db.execute("INSERT INTO feed_events VALUES(7,?1,'{}',?2)",params![path,format!("{:064x}",7)]).unwrap();f.db.execute("INSERT INTO publication_times VALUES(7,1)",[]).unwrap();
        f.step();assert!(!f.retention.policy.release_checkpoint.exists());assert_eq!(f.db.query_row("SELECT count(*) FROM banks",[],|r|r.get::<_,u64>(0)).unwrap(),3);
    }
    #[test]
    fn sparse_gap_release_requires_its_own_ack_and_exact_receipt(){
        let mut f=fixture();let gap=json!({"gap":{"schema":"hivezilla-incomplete-bank-gap-v1","producer_generation":f.retention.generation,"gap_sequence":7,"slot":88,"bank_id":9,"first_source_sequence":11,"last_source_sequence":17,"evidence_sha256":"b".repeat(64),"complete_bank":false,"captured_input_preserved":true}});
        record_gap(&mut f.db,7,&f.retention.generation,&gap).unwrap();f.acknowledge(6,0);f.step();let first=f.checkpoint();assert_eq!(first.released_banks.len(),2);f.receipt(&first);f.step();assert_eq!(f.db.query_row("SELECT count(*) FROM coverage_gaps",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        f.acknowledge(6,7);f.step();let next=f.checkpoint();assert_eq!(next.release_id,2);assert_eq!(next.released_banks[0].gap_sequence,Some(7));assert_eq!(next.released_banks[0].artifact,None);
        f.receipt(&next);let path=f.retention.processed.join("retention/release-2.json");let mut wrong:Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();wrong["processed_through_sequence"]=json!(999);atomic_json(&path,&wrong).unwrap();
        assert!(f.retention.pending(&mut f.db).unwrap_err().to_string().contains("frontier/count"));
    }
    #[test]
    fn every_registered_consumer_must_commit_before_release(){
        let mut f=fixture();f.acknowledge(6,0);
        f.ack.execute("UPDATE ack_binding SET json=?1",[json!({"schema":"blockzilla-consumer-ack-config-v1","source":f.retention.source,"consumers":["sidecar-primary","audit"]}).to_string()]).unwrap();
        f.step();assert!(!f.retention.policy.release_checkpoint.exists());
        f.ack.execute("INSERT INTO consumer_acks VALUES('audit',2,?1,0)",[v2::cursor(&f.retention.source.session_id,2,&format!("{:064x}",2))]).unwrap();f.step();let c=f.checkpoint();assert_eq!(c.released_banks.len(),1);assert_eq!(c.released_banks[0].bank_id,1);
    }
    #[test]
    fn complete_expiry_preserves_payload_until_its_gap_ack(){
        let mut f=fixture();f.db.execute("UPDATE banks SET state='published' WHERE bank=1",[]).unwrap();
        let(path,raw):(String,String)=f.db.query_row("SELECT artifact,payload_event FROM banks WHERE bank=1",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();let event:v2::BankEvent=serde_json::from_str(&raw).unwrap();
        let gap=json!({"gap":{"schema":"hivezilla-nonterminal-bank-gap-v1","producer_generation":f.retention.generation,"gap_sequence":7,"slot":101,"bank_id":1,"first_source_sequence":11,"last_source_sequence":17,"evidence_sha256":"b".repeat(64),"complete_bank":true,"captured_input_preserved":true,"reason":"complete-unconfirmed-bank-expired","canonical_status":"UNKNOWN","bank_identity":event.bank,"custody":{"artifact":path,"marker_sha256":event.payload_sha256}}});
        record_gap(&mut f.db,7,&f.retention.generation,&gap).unwrap();f.acknowledge(6,0);f.step();assert!(!f.retention.policy.release_checkpoint.exists());
        f.acknowledge(6,7);f.step();let c=f.checkpoint();let expired=c.released_banks.iter().find(|b|b.bank_id==1).unwrap();assert_eq!(expired.artifact.as_deref(),Some(path.as_str()));assert_eq!(expired.gap_sequence,Some(7));assert_eq!(expired.evidence_sha256,Some("b".repeat(64)));
    }
    #[test]
    fn orphan_slot_controls_have_explicit_gap_ack_and_no_fabricated_bank(){
        let mut f=fixture();f.acknowledge(6,0);f.step();let first=f.checkpoint();f.receipt(&first);f.step();
        let gap=json!({"gap":{"schema":"hivezilla-slot-control-gap-v1","producer_generation":f.retention.generation,"gap_sequence":7,"slot":88,"bank_id":null,"bank_identity":null,"first_source_sequence":11,"last_source_sequence":17,"evidence_sha256":"b".repeat(64),"complete_bank":false,"captured_input_preserved":true}});
        record_gap(&mut f.db,7,&f.retention.generation,&gap).unwrap();f.step();assert_eq!(f.checkpoint().release_id,1);
        f.acknowledge(6,7);f.step();let c=f.checkpoint();assert_eq!(c.release_id,2);assert!(c.released_banks.is_empty());assert_eq!(c.released_slot_controls.len(),1);assert_eq!(c.released_slot_controls[0].slot,88);assert_eq!(c.released_slot_controls[0].gap_sequence,7);
        assert_eq!(f.db.query_row("SELECT count(*) FROM banks",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        assert_eq!(f.db.query_row("SELECT gap_base_sequence FROM feed_retention",[],|r|r.get::<_,u64>(0)).unwrap(),7);
    }
    #[test]
    fn delayed_controls_larger_than_release_batch_make_bounded_prefix_progress(){
        let mut f=fixture_n(101);f.db.execute_batch("DELETE FROM feed_events;DELETE FROM publication_times;").unwrap();
        for n in 1..=101u64 {
            let(path,raw):(String,String)=f.db.query_row("SELECT artifact,payload_event FROM banks WHERE bank=?1",[n],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
            let block=if n==101{201}else{n};let root=if n==101{202}else{100+n};
            for sequence in [block,root]{f.db.execute("INSERT INTO feed_events VALUES(?1,?2,?3,?4)",params![sequence,path,raw,format!("{sequence:064x}")]).unwrap();f.db.execute("INSERT INTO publication_times VALUES(?1,1)",[sequence]).unwrap();}
            f.db.execute("UPDATE input_commits SET last_event_sequence=?2 WHERE processed_sequence=?1",params![n,root]).unwrap();
        }
        f.acknowledge(202,0);f.step();let first=f.checkpoint();assert!(first.released_banks.is_empty());assert_eq!(v2::parse_cursor(&first.replay_floor_cursor).unwrap().1,64);
        f.receipt(&first);
        for _ in 0..8 {f.step();let c=f.checkpoint();f.receipt(&c);if f.db.query_row("SELECT count(*) FROM banks",[],|r|r.get::<_,u64>(0)).unwrap()==1{break;}}
        assert_eq!(f.db.query_row("SELECT count(*) FROM banks",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        assert_eq!(f.db.query_row("SELECT base_sequence FROM feed_retention",[],|r|r.get::<_,u64>(0)).unwrap(),200);
        assert_eq!(f.db.query_row("SELECT bank FROM banks",[],|r|r.get::<_,u64>(0)).unwrap(),101);
    }
    #[test]
    fn coverage_ack_ahead_of_native_ack_waits_without_failing_or_releasing_gap(){
        let mut f=fixture();let gap=json!({"gap":{"schema":"hivezilla-incomplete-bank-gap-v1","producer_generation":f.retention.generation,"gap_sequence":7,"slot":88,"bank_id":9,"first_source_sequence":11,"last_source_sequence":17,"evidence_sha256":"b".repeat(64),"complete_bank":false,"captured_input_preserved":true}});
        record_gap(&mut f.db,7,&f.retention.generation,&gap).unwrap();f.acknowledge(2,7);f.step();let first=f.checkpoint();assert_eq!(first.processed_through_sequence,1);assert!(first.released_banks.iter().all(|b|b.gap_sequence.is_none()));assert_eq!(f.db.query_row("SELECT count(*) FROM coverage_gaps",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        f.receipt(&first);f.step();assert_eq!(f.checkpoint(),first);
        f.acknowledge(6,7);f.step();let next=f.checkpoint();assert_eq!(next.processed_through_sequence,7);assert!(next.released_banks.iter().any(|b|b.gap_sequence==Some(7)));assert_eq!(f.db.query_row("SELECT count(*) FROM coverage_gaps",[],|r|r.get::<_,u64>(0)).unwrap(),0);
    }
    #[test]
    fn local_window_ignores_absent_or_stalled_consumers_and_preserves_age_gate(){
        let mut f=fixture();f.retention.local_beam=true;f.retention.bind_authority(&mut f.db).unwrap();
        f.ack.execute_batch("DROP TABLE ack_binding;DROP TABLE consumer_acks;").unwrap();
        f.retention.policy.min_retention_ms=u64::MAX;f.step();assert!(!f.retention.policy.release_checkpoint.exists());
        f.retention.policy.min_retention_ms=0;f.step();let first=f.checkpoint();
        assert_eq!(first.released_banks.len(),2);assert_eq!(first.acknowledged_cursor,v2::cursor(&f.retention.source.session_id,6,&format!("{:064x}",6)));
        assert_eq!(f.db.query_row("SELECT count(*) FROM banks",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        fs::remove_file(&f.retention.policy.release_checkpoint).unwrap();f.step();assert_eq!(f.checkpoint(),first);
        f.receipt(&first);f.step();
        assert_eq!(f.db.query_row("SELECT completed FROM release_jobs WHERE id=1",[],|r|r.get::<_,u64>(0)).unwrap(),1);
    }
    #[test]
    fn local_window_policy_transition_is_durable_source_bound_and_one_way(){
        let mut f=fixture();f.retention.bind_authority(&mut f.db).unwrap();
        let old=fs::read(f.retention.output.join("RETENTION-AUTHORITY.json")).unwrap();
        f.retention.local_beam=true;f.retention.bind_authority(&mut f.db).unwrap();
        let descriptor=f.retention.output.join("RETENTION-AUTHORITY.json");
        let wanted=f.retention.authority();assert_eq!(serde_json::from_slice::<Value>(&fs::read(&descriptor).unwrap()).unwrap(),wanted);
        // A crash after the FULL row and before its file projection repairs it.
        fs::write(&descriptor,&old).unwrap();f.retention.bind_authority(&mut f.db).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&fs::read(&descriptor).unwrap()).unwrap(),wanted);
        f.retention.local_beam=false;assert!(f.retention.bind_authority(&mut f.db).is_err());
        f.retention.local_beam=true;f.retention.generation="b".repeat(64);assert!(f.retention.bind_authority(&mut f.db).is_err());
    }
    #[test]
    fn local_window_requires_current_tip_and_keeps_later_control_dependency(){
        let mut f=fixture();f.retention.local_beam=true;
        let path:String=f.db.query_row("SELECT artifact FROM banks WHERE bank=1",[],|r|r.get(0)).unwrap();
        f.db.execute("INSERT INTO feed_events VALUES(7,?1,'{}',?2)",params![path,format!("{:064x}",7)]).unwrap();
        f.db.execute("INSERT INTO publication_times VALUES(7,1)",[]).unwrap();f.db.execute("UPDATE feed_state SET event_sequence=7",[]).unwrap();
        f.step();let c=f.checkpoint();assert!(c.released_banks.iter().all(|b|b.bank_id!=1));
        assert_eq!(f.db.query_row("SELECT count(*) FROM banks WHERE bank=1",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        assert_eq!(f.db.query_row("SELECT count(*) FROM feed_events WHERE sequence=7",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        f.db.execute("DELETE FROM feed_events WHERE sequence=7",[]).unwrap();
        assert!(f.retention.frontier(&f.db).is_err());
        f.db.execute("UPDATE feed_retention SET base_sequence=7,base_sha256=?1",[format!("{:064x}",7)]).unwrap();
        assert_eq!(f.retention.frontier(&f.db).unwrap().unwrap().1,7);
    }
    #[test]
    fn local_gap_custody_is_durable_before_source_release_without_consumer_receipt(){
        let mut f=fixture();f.retention.local_beam=true;f.retention.bind_authority(&mut f.db).unwrap();
        let raw=json!({"gap":{"schema":"hivezilla-slot-control-gap-v1","producer_generation":f.retention.generation,"gap_sequence":7,"slot":88,"bank_id":null,"bank_identity":null,"first_source_sequence":11,"last_source_sequence":17,"evidence_sha256":"b".repeat(64),"complete_bank":false,"captured_input_preserved":true}});
        record_gap(&mut f.db,7,&f.retention.generation,&raw).unwrap();f.step();let c=f.checkpoint();
        assert_eq!(c.processed_through_sequence,7);assert_eq!(c.released_slot_controls.len(),1);
        assert_eq!(f.db.query_row("SELECT gap_json FROM local_gap_history WHERE sequence=7",[],|r|r.get::<_,String>(0)).unwrap(),serde_json::to_string(&raw["gap"]).unwrap());
        assert_eq!(f.ack.query_row("SELECT count(*) FROM consumer_acks",[],|r|r.get::<_,u64>(0)).unwrap(),0);
        assert_eq!(f.db.query_row("SELECT count(*) FROM coverage_gaps",[],|r|r.get::<_,u64>(0)).unwrap(),0);
    }
}
