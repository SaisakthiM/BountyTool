//! Rate limiting: a global token bucket plus a per-host request budget.
//!
//! Two independent brakes so a scan can never turn into a denial of service:
//! a scan-wide requests-per-second cap and a hard per-host ceiling.

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

/// Default per-host budget when configuration does not set one.
pub const DEFAULT_PER_HOST_BUDGET: u32 = 300;

pub struct Limiter {
    interval: Duration,
    next_slot: StdMutex<tokio::time::Instant>,
    budgets: StdMutex<HashMap<String, u32>>,
    per_host_budget: u32,
}

impl Limiter {
    pub fn new(requests_per_second: u32, per_host_budget: u32) -> Limiter {
        let rps = u64::from(requests_per_second.max(1));
        Limiter {
            // Nanoseconds keep the spacing exact: whole milliseconds would round
            // anything above 1000 rps down to zero and disable throttling.
            interval: Duration::from_nanos(1_000_000_000 / rps),
            next_slot: StdMutex::new(tokio::time::Instant::now()),
            budgets: StdMutex::new(HashMap::new()),
            per_host_budget: if per_host_budget == 0 {
                DEFAULT_PER_HOST_BUDGET
            } else {
                per_host_budget
            },
        }
    }

    pub fn per_host_budget(&self) -> u32 {
        self.per_host_budget
    }

    /// Wait for a rate-limit slot. Returns `false` when the host budget is
    /// exhausted, which callers treat as "skip this host".
    pub async fn acquire(&self, host: &str) -> bool {
        if !self.spend_budget(host) {
            return false;
        }
        self.wait_for_slot().await;
        true
    }

    /// Reserve a slot without sending anything; used by dry runs.
    pub fn take_budget(&self, host: &str) -> bool {
        self.spend_budget(host)
    }

    pub fn remaining(&self, host: &str) -> u32 {
        self.budgets
            .lock()
            .map(|budgets| *budgets.get(host).unwrap_or(&self.per_host_budget))
            .unwrap_or(0)
    }

    fn spend_budget(&self, host: &str) -> bool {
        let Ok(mut budgets) = self.budgets.lock() else {
            return false;
        };
        let entry = budgets
            .entry(host.to_string())
            .or_insert(self.per_host_budget);
        if *entry == 0 {
            return false;
        }
        *entry -= 1;
        true
    }

    async fn wait_for_slot(&self) {
        // Reserve a slot under the lock, then sleep until it. Retrying in a loop
        // while pushing the deadline forward would never converge: each pass
        // would move the target further into the future.
        let reserved = {
            let Ok(mut next) = self.next_slot.lock() else {
                return;
            };
            let now = tokio::time::Instant::now();
            if now >= *next {
                *next = now + self.interval;
                None
            } else {
                let at = *next;
                *next = at + self.interval;
                Some(at)
            }
        };
        if let Some(at) = reserved {
            tokio::time::sleep_until(at).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn per_host_budget_is_enforced() {
        let limiter = Limiter::new(10_000, 2);
        assert!(limiter.acquire("a.test").await);
        assert!(limiter.acquire("a.test").await);
        assert!(!limiter.acquire("a.test").await);
        assert_eq!(limiter.remaining("a.test"), 0);
        // A different host still has its own budget.
        assert!(limiter.acquire("b.test").await);
        assert_eq!(limiter.remaining("b.test"), 1);
    }

    #[tokio::test]
    async fn rate_limiting_spaces_requests() {
        let limiter = Limiter::new(50, 100);
        let start = std::time::Instant::now();
        for _ in 0..5 {
            limiter.acquire("a.test").await;
        }
        // 50 rps -> 20ms per slot, 5 slots ~= 80ms of spacing.
        assert!(start.elapsed() >= Duration::from_millis(60));
    }
}
