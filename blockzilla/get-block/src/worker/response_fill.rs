//! Share one response-cache fill among concurrent requests in one isolate.
//! No response bytes are retained here. Auth runs before admission, and each
//! follower reads the existing response cache only after the fill completes.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};

const MAX_FILLS: usize = 64;
const MAX_FOLLOWERS: usize = 32;
const MAX_KEY_BYTES: usize = 1024;
const MAX_FILL_AGE_MS: f64 = 30_000.0;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Pending,
    Cached,
    Failed,
}

pub(super) struct Follower {
    state: Rc<Cell<State>>,
}

struct Entry {
    state: Rc<Cell<State>>,
    followers: usize,
    started_ms: f64,
}

thread_local! {
    static FILLS: RefCell<BTreeMap<String, Entry>> = RefCell::default();
}

pub(super) enum Admission {
    Leader(Leader),
    Follower(Follower),
    Untracked,
}

pub(super) struct Leader {
    key: String,
    state: Rc<Cell<State>>,
    finished: bool,
}

pub(super) fn admit(key: &str) -> Admission {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Admission::Untracked;
    }
    let now = super::now_ms();
    FILLS.with(|fills| {
        let mut fills = fills.borrow_mut();
        fills.retain(|_, entry| {
            let keep =
                entry.state.get() == State::Pending && now - entry.started_ms < MAX_FILL_AGE_MS;
            if !keep && entry.state.get() == State::Pending {
                entry.state.set(State::Failed);
            }
            keep
        });
        if let Some(entry) = fills.get_mut(key) {
            if entry.followers >= MAX_FOLLOWERS {
                return Admission::Untracked;
            }
            entry.followers += 1;
            return Admission::Follower(Follower {
                state: entry.state.clone(),
            });
        }
        if fills.len() >= MAX_FILLS {
            return Admission::Untracked;
        }
        let state = Rc::new(Cell::new(State::Pending));
        fills.insert(
            key.into(),
            Entry {
                state: state.clone(),
                followers: 0,
                started_ms: now,
            },
        );
        Admission::Leader(Leader {
            key: key.into(),
            state,
            finished: false,
        })
    })
}

impl Leader {
    pub(super) fn finish(mut self, cached: bool) {
        self.signal(cached);
    }

    fn signal(&mut self, cached: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        FILLS.with(|fills| {
            let mut fills = fills.borrow_mut();
            if fills
                .get(&self.key)
                .is_some_and(|entry| Rc::ptr_eq(&entry.state, &self.state))
            {
                fills.remove(&self.key);
            }
        });
        self.state
            .set(if cached { State::Cached } else { State::Failed });
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        // Every early error or cancellation releases the slot and marks failure.
        self.signal(false);
    }
}

pub(super) async fn wait(follower: Follower) -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        // Cross-request future wakers can resume a follower in the leader's
        // Workers I/O context. Share only status and use request-local timers.
        let started = super::now_ms();
        for _ in 0..80 {
            match follower.state.get() {
                State::Cached => return true,
                State::Failed => return false,
                State::Pending => {}
            }
            if super::now_ms() - started >= 2000.0 {
                return false;
            }
            worker::Delay::from(std::time::Duration::from_millis(25)).await;
        }
        follower.state.get() == State::Cached
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        follower.state.get() == State::Cached
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_is_shared_and_releases_the_key() {
        let Admission::Leader(leader) = admit("complete") else {
            panic!()
        };
        let Admission::Follower(first) = admit("complete") else {
            panic!()
        };
        let Admission::Follower(second) = admit("complete") else {
            panic!()
        };
        leader.finish(true);
        assert_eq!(first.state.get(), State::Cached);
        assert_eq!(second.state.get(), State::Cached);
        assert!(matches!(admit("complete"), Admission::Leader(_)));
    }

    #[test]
    fn cancelled_leader_wakes_followers_without_claiming_cache_success() {
        let Admission::Leader(leader) = admit("cancelled") else {
            panic!()
        };
        let Admission::Follower(follower) = admit("cancelled") else {
            panic!()
        };
        drop(leader);
        assert_eq!(follower.state.get(), State::Failed);
        assert!(matches!(admit("cancelled"), Admission::Leader(_)));
    }

    #[test]
    fn bounded_fills_followers_and_keys() {
        assert!(matches!(admit(""), Admission::Untracked));
        assert!(matches!(
            admit(&"x".repeat(MAX_KEY_BYTES + 1)),
            Admission::Untracked
        ));
        let leaders: Vec<_> = (0..MAX_FILLS)
            .map(|i| {
                let Admission::Leader(leader) = admit(&format!("bound-{i}")) else {
                    panic!()
                };
                leader
            })
            .collect();
        assert!(matches!(admit("overflow"), Admission::Untracked));
        let followers: Vec<_> = (0..MAX_FOLLOWERS)
            .map(|_| {
                let Admission::Follower(follower) = admit("bound-0") else {
                    panic!()
                };
                follower
            })
            .collect();
        assert!(matches!(admit("bound-0"), Admission::Untracked));
        drop(leaders);
        assert!(
            followers
                .into_iter()
                .all(|f| f.state.get() == State::Failed)
        );
        assert!(matches!(admit("overflow"), Admission::Leader(_)));
    }

    #[test]
    fn stale_leader_does_not_remove_a_replacement() {
        let Admission::Leader(old) = admit("stale") else {
            panic!()
        };
        FILLS.with(|fills| {
            fills.borrow_mut().get_mut("stale").unwrap().started_ms = f64::NEG_INFINITY;
        });
        let Admission::Leader(new) = admit("stale") else {
            panic!()
        };
        drop(old);
        let Admission::Follower(follower) = admit("stale") else {
            panic!()
        };
        assert_eq!(follower.state.get(), State::Pending);
        new.finish(true);
        assert_eq!(follower.state.get(), State::Cached);
    }
}
