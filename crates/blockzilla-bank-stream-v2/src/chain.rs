//! Confirmation is bank-bound. An old control never renews a newer observation.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_BANKS: usize = 16_384;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BankState {
    pub bank: BankIdentity,
    pub payload_sha256: String,
    pub payload_frame_sha256: String,
    pub block_height: u64,
    pub invalidated: bool,
    pub rooted: bool,
    pub confirmed: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub banks: BTreeMap<String, BankState>,
    pub latest: Option<ConfirmedObservation>,
    pub boundary: Option<(u64, [u8; 32])>,
    pub reconciliate: bool,
}
fn key(b: &BankIdentity) -> String {
    format!("{}:{}", b.slot, b.bank_id)
}
impl Chain {
    pub fn validate(&self, source: &SourceIdentity, cursor: &str) -> Result<()> {
        ensure!(self.banks.len() <= MAX_BANKS, "bank_queue_overflow");
        let (session, sequence, _) = parse_cursor(cursor)?;
        ensure!(session == source.session_id, "source_changed");
        for (k, b) in &self.banks {
            b.bank.validate()?;
            ensure!(
                *k == key(&b.bank)
                    && b.block_height <= SAFE
                    && is_digest(&b.payload_sha256)
                    && is_digest(&b.payload_frame_sha256)
                    && !(b.rooted && b.invalidated),
                "invalid_chain_state"
            );
        }
        if let Some((slot, _)) = self.boundary {
            ensure!(slot <= SAFE, "invalid_chain_boundary");
        }
        if let Some(c) = &self.latest {
            c.bank.validate()?;
            c.recent_blockhash.validate(&c.bank, c.block_height)?;
            let (session, n, sha) = parse_cursor(&c.event_cursor)?;
            let b = self
                .banks
                .get(&key(&c.bank))
                .context("head_bank_unavailable")?;
            ensure!(
                session == source.session_id
                    && n == c.event_sequence
                    && n > 0
                    && n <= sequence
                    && is_digest(sha)
                    && b.bank == c.bank
                    && b.payload_sha256 == c.payload_sha256
                    && b.payload_frame_sha256 == c.payload_frame_sha256
                    && b.block_height == c.block_height
                    && b.confirmed
                    && !b.invalidated
                    && matches!(c.commitment.as_str(), "confirmed" | "finalized"),
                "invalid_chain_head"
            );
            self.resolved(&c.bank)?;
        }
        Ok(())
    }
    pub fn add_payload(&mut self, f: &Frame) -> Result<()> {
        let e = &f.envelope.event;
        ensure!(e.kind == "block", "not_payload");
        let k = key(&e.bank);
        if let Some(old) = self.banks.get(&k) {
            ensure!(
                old.bank == e.bank
                    && old.payload_sha256 == e.payload_sha256
                    && old.payload_frame_sha256 == f.sha256,
                "contradictory_bank"
            );
            return Ok(());
        }
        ensure!(self.banks.len() < MAX_BANKS, "bank_queue_overflow");
        self.banks.insert(
            k,
            BankState {
                bank: e.bank.clone(),
                payload_sha256: e.payload_sha256.clone(),
                payload_frame_sha256: f.sha256.clone(),
                block_height: e.block_height.context("missing_height")?,
                invalidated: false,
                rooted: false,
                confirmed: false,
            },
        );
        Ok(())
    }
    pub fn seed(&mut self, observation: ConfirmedObservation, payload: &Frame) -> Result<()> {
        self.add_payload(payload)?;
        let b = self
            .banks
            .get_mut(&key(&observation.bank))
            .context("missing_payload")?;
        ensure!(
            b.bank == observation.bank
                && b.payload_sha256 == observation.payload_sha256
                && b.payload_frame_sha256 == observation.payload_frame_sha256
                && b.block_height == observation.block_height,
            "head_payload_mismatch"
        );
        b.confirmed = true;
        b.rooted = observation.commitment == "finalized";
        self.boundary = Some((b.bank.parent_slot, b.bank.parent_blockhash));
        self.latest = Some(observation);
        Ok(())
    }
    fn resolved(&self, bank: &BankIdentity) -> Result<Vec<String>> {
        let mut chain = Vec::new();
        let mut current = bank.clone();
        let mut visited = BTreeSet::new();
        loop {
            let k = key(&current);
            ensure!(visited.insert(k.clone()), "parent_cycle");
            let state = self.banks.get(&k).context("dependency_unavailable")?;
            ensure!(
                state.bank == current && !state.invalidated,
                "invalidated_ancestry"
            );
            chain.push(k);
            if state.rooted
                || self.boundary == Some((current.parent_slot, current.parent_blockhash))
            {
                return Ok(chain);
            }
            let mut parents = self
                .banks
                .values()
                .filter(|p| current.parent_matches(&p.bank) && !p.invalidated);
            let parent = parents.next().context("dependency_unavailable")?;
            ensure!(parents.next().is_none(), "ambiguous_parent_bank");
            ensure!(
                parent.block_height.checked_add(1) == Some(state.block_height),
                "parent_height_mismatch"
            );
            current = parent.bank.clone();
        }
    }
    pub fn can_confirm(&self, bank: &BankIdentity) -> Result<()> {
        self.resolved(bank).map(|_| ())
    }
    /// Return the complete captured path after a caller's committed anchor.
    /// The root is backed by an exact native root control. Both endpoints must
    /// remain known, and every intervening parent and native height must match.
    /// Existing rooted nodes and partial capture boundaries do not skip history.
    /// This does not establish coverage before the anchor or select a new head.
    pub fn rooted_path_after(
        &self,
        root: &BankIdentity,
        anchor: &BankIdentity,
        anchor_height: u64,
    ) -> Result<Vec<BankState>> {
        root.validate()?;
        anchor.validate()?;
        ensure!(
            self.banks.len() <= MAX_BANKS && anchor_height <= SAFE,
            "invalid_chain_state"
        );
        let mut current = self
            .banks
            .get(&key(root))
            .context("root_bank_unavailable")?;
        ensure!(
            current.bank == *root && current.rooted && current.confirmed && !current.invalidated,
            "root_not_admitted"
        );
        let anchor_state = self
            .banks
            .get(&key(anchor))
            .context("anchor_bank_unavailable")?;
        ensure!(
            anchor_state.bank == *anchor
                && !anchor_state.invalidated
                && anchor_state.block_height == anchor_height,
            "anchor_bank_mismatch"
        );
        let mut reverse = Vec::new();
        let mut visited = BTreeSet::new();
        loop {
            ensure!(visited.insert(key(&current.bank)), "parent_cycle");
            Self::path_state(current)?;
            if current.bank == *anchor {
                ensure!(
                    current.block_height == anchor_height,
                    "anchor_height_mismatch"
                );
                reverse.reverse();
                return Ok(reverse);
            }
            ensure!(
                current.bank.slot > anchor.slot && current.block_height > anchor_height,
                "root_not_descendant_of_anchor"
            );
            reverse.push(current.clone());
            current = self
                .known_parent(current)?
                .context("dependency_unavailable")?;
        }
    }
    /// Return captured banks after an explicitly admitted bootstrap parent.
    /// Unlike `rooted_path_after`, the excluded parent need not be captured.
    /// No history or rooted status is asserted for that parent or its prefix.
    pub fn rooted_path_from_boundary(
        &self,
        root: &BankIdentity,
        boundary_slot: u64,
        boundary_hash: [u8; 32],
        boundary_height: u64,
    ) -> Result<Vec<BankState>> {
        root.validate()?;
        ensure!(
            self.banks.len() <= MAX_BANKS && boundary_slot <= SAFE && boundary_height <= SAFE,
            "invalid_capture_boundary"
        );
        let mut current = self
            .banks
            .get(&key(root))
            .context("root_bank_unavailable")?;
        ensure!(
            current.bank == *root && current.rooted && current.confirmed && !current.invalidated,
            "root_not_admitted"
        );
        if root.slot == boundary_slot {
            Self::path_state(current)?;
            ensure!(
                root.blockhash == boundary_hash && current.block_height == boundary_height,
                "capture_boundary_root_mismatch"
            );
            return Ok(Vec::new());
        }
        let mut reverse = Vec::new();
        let mut visited = BTreeSet::new();
        loop {
            ensure!(visited.insert(key(&current.bank)), "parent_cycle");
            Self::path_state(current)?;
            ensure!(
                current.bank.slot > boundary_slot && current.block_height > boundary_height,
                "root_before_capture_boundary"
            );
            reverse.push(current.clone());
            let parent = self.known_parent(current)?;
            if current.bank.parent_slot == boundary_slot
                && current.bank.parent_blockhash == boundary_hash
            {
                ensure!(
                    boundary_height.checked_add(1) == Some(current.block_height),
                    "parent_height_mismatch"
                );
                reverse.reverse();
                return Ok(reverse);
            }
            current = parent.context("dependency_unavailable")?;
        }
    }
    fn path_state(state: &BankState) -> Result<()> {
        state.bank.validate()?;
        ensure!(!state.invalidated, "invalidated_ancestry");
        ensure!(
            state.block_height <= SAFE
                && is_digest(&state.payload_sha256)
                && is_digest(&state.payload_frame_sha256),
            "invalid_chain_state"
        );
        Ok(())
    }
    fn known_parent(&self, state: &BankState) -> Result<Option<&BankState>> {
        let mut parents = self
            .banks
            .values()
            .filter(|p| state.bank.parent_matches(&p.bank) && !p.invalidated);
        let parent = parents.next();
        ensure!(parents.next().is_none(), "ambiguous_parent_bank");
        if let Some(parent) = parent {
            ensure!(
                parent.block_height.checked_add(1) == Some(state.block_height),
                "parent_height_mismatch"
            );
        } else {
            ensure!(
                !self
                    .banks
                    .values()
                    .any(|p| state.bank.parent_matches(&p.bank) && p.invalidated),
                "invalidated_ancestry"
            );
        }
        Ok(parent)
    }
    /// An exact native control before the retained/captured prefix admits only
    /// its own bank. It does not connect the missing prefix, select a head, or
    /// advance the boundary. A confirmed control does not establish a root.
    fn control_before_boundary(&self, bank: &BankIdentity) -> Result<bool> {
        let Some((slot, hash)) = self.boundary else {
            return Ok(false);
        };
        let capture_height = match &self.latest {
            Some(latest) => latest.block_height,
            None => {
                // A processed capture starts replay before its confirmed control.
                // Its exact parent boundary and native child height admit only
                // separate older controls, without selecting a confirmed head.
                let mut children = self.banks.values().filter(|b| {
                    !b.invalidated && b.bank.parent_slot == slot && b.bank.parent_blockhash == hash
                });
                let Some(child) = children.next() else {
                    return Ok(false);
                };
                Self::path_state(child)?;
                for other in children {
                    Self::path_state(other)?;
                    ensure!(
                        other.block_height == child.block_height,
                        "capture_boundary_height_mismatch"
                    );
                }
                child.block_height
            }
        };
        let state = self
            .banks
            .get(&key(bank))
            .context("control_bank_unavailable")?;
        if bank.slot > slot || state.block_height >= capture_height {
            return Ok(false);
        }
        ensure!(
            state.bank == *bank && !state.invalidated,
            "invalidated_ancestry"
        );
        if bank.slot == slot {
            ensure!(bank.blockhash == hash, "capture_boundary_root_mismatch");
            for child in self
                .banks
                .values()
                .filter(|b| b.bank.parent_slot == slot && b.bank.parent_blockhash == hash)
            {
                ensure!(
                    state.block_height.checked_add(1) == Some(child.block_height),
                    "parent_height_mismatch"
                );
            }
        }
        let mut current = state;
        let mut visited = BTreeSet::new();
        loop {
            ensure!(visited.insert(key(&current.bank)), "parent_cycle");
            Self::path_state(current)?;
            if current.rooted {
                return Ok(true);
            }
            match self.known_parent(current)? {
                Some(parent) => current = parent,
                // Native evidence admits this bank, not uncaptured parents.
                None => return Ok(true),
            }
        }
    }
    pub fn apply_control(&mut self, frame: &Frame, payload: &Frame) -> Result<()> {
        let e = &frame.envelope.event;
        e.validate()?;
        e.matches_payload(payload)?;
        ensure!(frame.source == payload.source, "source_changed");
        self.add_payload(payload)?;
        let k = key(&e.bank);
        if e.kind == "invalidate" {
            let mut removed = BTreeSet::from([k.clone()]);
            loop {
                let next: Vec<_> = self
                    .banks
                    .iter()
                    .filter(|(k, b)| {
                        !removed.contains(*k)
                            && self.banks.iter().any(|(p, parent)| {
                                removed.contains(p) && b.bank.parent_matches(&parent.bank)
                            })
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                if next.is_empty() {
                    break;
                }
                removed.extend(next);
            }
            ensure!(
                !removed.iter().any(|k| self.banks[k].rooted),
                "rooted_bank_invalidated"
            );
            let confirmed = removed.iter().any(|k| self.banks[k].confirmed);
            for k in &removed {
                self.banks.get_mut(k).unwrap().invalidated = true;
            }
            if self
                .latest
                .as_ref()
                .is_some_and(|h| removed.contains(&key(&h.bank)))
            {
                self.latest = None;
            }
            self.reconciliate |= confirmed;
            return Ok(());
        }
        // The first exact native root is the trusted capture boundary. We do
        // not claim confirmation for uncaptured ancestors below that boundary.
        if e.kind == "root" && self.latest.is_none() && self.boundary.is_none() {
            self.boundary = Some((e.bank.parent_slot, e.bank.parent_blockhash));
        }
        let detached = matches!(e.kind.as_str(), "root" | "confirmed")
            && self.control_before_boundary(&e.bank)?;
        if !detached {
            self.resolved(&e.bank)?;
        }
        let state = self.banks.get_mut(&k).unwrap();
        ensure!(
            state.block_height == e.block_height.context("missing_height")?,
            "confirmation_height_mismatch"
        );
        state.confirmed = true;
        state.rooted |= e.kind == "root";
        let next = ConfirmedObservation::from_frame(frame)?;
        if !detached
            && self
                .latest
                .as_ref()
                .is_none_or(|old| next.block_height > old.block_height)
        {
            self.latest = Some(next);
        }
        // Keep the latest root as the admitted ancestry anchor. The replay store
        // independently retains payload dependencies for older control events.
        if e.kind == "root" {
            let root_height = state.block_height;
            let root_bank = state.bank.clone();
            let selected_below = self
                .latest
                .as_ref()
                .is_some_and(|c| c.block_height < root_height);
            ensure!(!selected_below, "root_replaced_newer_head");
            let incompatible: Vec<_> = self
                .banks
                .iter()
                .filter(|(_, b)| {
                    b.block_height >= root_height
                        && b.bank != root_bank
                        && b.bank.slot == root_bank.slot
                })
                .map(|(k, _)| k.clone())
                .collect();
            ensure!(
                !incompatible
                    .iter()
                    .any(|k| self.banks[k].confirmed && !self.banks[k].invalidated),
                "competing_confirmed_root"
            );
            // A detached older root cannot move the newer capture boundary.
            if self.banks.len() > MAX_BANKS / 2 && !detached {
                let floor = root_height.saturating_sub(4096);
                self.banks.retain(|_, b| b.block_height >= floor);
                if let Some(first) = self.banks.values().min_by_key(|b| b.block_height) {
                    self.boundary = Some((first.bank.parent_slot, first.bank.parent_blockhash));
                }
            }
        }
        Ok(())
    }
}
