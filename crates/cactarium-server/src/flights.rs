//! Work shared between concurrent requests: the first request for a key computes the value, and
//! the others that arrive meanwhile wait for it instead of repeating it. Values are kept for a
//! while afterwards, as a cache.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::OnceCell;

pub struct Flights<K, V> {
    cells: Mutex<HashMap<K, (Instant, Arc<OnceCell<V>>)>>,
    /// How long a value is kept; None keeps it until the map is full.
    ttl: Option<Duration>,
    /// Past this many keys the map is cleared (the values are cheap to recompute, just not free).
    cap: usize,
}

impl<K: Eq + Hash + Clone, V: Clone> Flights<K, V> {
    pub fn new(ttl: Option<Duration>, cap: usize) -> Self {
        Flights { cells: Mutex::new(HashMap::new()), ttl, cap }
    }

    /// The value for `key`, computing it with `make` unless it is known or being computed. A
    /// failure isn't kept: the next request tries again. If the request computing it goes away,
    /// one of the waiting ones takes over.
    pub async fn get_or_try_init<E, F, Fut>(&self, key: K, make: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let cell = {
            let mut cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            if let Some(ttl) = self.ttl {
                cells.retain(|_, (made, _)| now.duration_since(*made) < ttl);
            }
            if cells.len() >= self.cap && !cells.contains_key(&key) {
                cells.clear();
            }
            cells.entry(key).or_insert_with(|| (now, Arc::new(OnceCell::new()))).1.clone()
        };
        cell.get_or_try_init(make).await.cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn concurrent_requests_share_one_computation() {
        let f: Arc<Flights<u32, u32>> = Arc::new(Flights::new(None, 10));
        let runs = Arc::new(AtomicUsize::new(0));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let (f, runs) = (f.clone(), runs.clone());
            set.spawn(async move {
                f.get_or_try_init(1, || async {
                    runs.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok::<_, ()>(7)
                })
                .await
            });
        }
        while let Some(r) = set.join_next().await {
            assert_eq!(r.unwrap(), Ok(7));
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failures_are_retried_and_values_expire() {
        let f: Flights<u32, u32> = Flights::new(Some(Duration::from_millis(30)), 10);
        assert_eq!(f.get_or_try_init(1, || async { Err::<u32, _>("no") }).await, Err("no"));
        assert_eq!(f.get_or_try_init(1, || async { Ok::<_, &str>(2) }).await, Ok(2));
        assert_eq!(f.get_or_try_init(1, || async { Ok::<_, &str>(3) }).await, Ok(2), "kept");
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(f.get_or_try_init(1, || async { Ok::<_, &str>(4) }).await, Ok(4), "expired");
    }
}
