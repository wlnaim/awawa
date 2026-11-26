//! Tabla de slots de hosts en espera: `DashMap<id, Slot>` con TTL.
//!
//! El tiempo entra siempre como argumento (`now`), de modo que la expiracion se prueba sin esperar.
//! Un slot se consume al emparejarse (`take`): es de un solo uso.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InsertError {
    /// Ya hay un slot vigente con ese ID.
    Taken,
    /// Se alcanzo el tope de slots.
    Full,
}

struct Slot<V> {
    value: V,
    nonce: u64,
    expires_at: Instant,
}

pub(crate) struct SlotTable<V> {
    map: DashMap<u32, Slot<V>>,
    ttl: Duration,
    max_slots: usize,
    next_nonce: AtomicU64,
}

impl<V> SlotTable<V> {
    pub(crate) fn new(ttl: Duration, max_slots: usize) -> Self {
        Self {
            map: DashMap::new(),
            ttl,
            max_slots,
            next_nonce: AtomicU64::new(1),
        }
    }

    pub(crate) fn ttl(&self) -> Duration {
        self.ttl
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Registra `value` bajo `id`. Un slot vencido se reemplaza; uno vigente rechaza la colision.
    /// Devuelve el nonce del slot, que identifica a su dueno en `remove_matching`.
    ///
    /// El tope es blando: bajo carrera concurrente puede excederse en unas pocas entradas.
    pub(crate) fn insert(&self, id: u32, value: V, now: Instant) -> Result<u64, InsertError> {
        if self.map.len() >= self.max_slots {
            return Err(InsertError::Full);
        }
        let nonce = self.next_nonce.fetch_add(1, Ordering::Relaxed);
        let slot = Slot {
            value,
            nonce,
            expires_at: now + self.ttl,
        };
        match self.map.entry(id) {
            Entry::Occupied(mut occupied) => {
                if occupied.get().expires_at <= now {
                    occupied.insert(slot);
                    Ok(nonce)
                } else {
                    Err(InsertError::Taken)
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(slot);
                Ok(nonce)
            }
        }
    }

    /// Retira y devuelve el slot si sigue vigente. Uno vencido se descarta y devuelve `None`.
    pub(crate) fn take(&self, id: u32, now: Instant) -> Option<V> {
        let (_, slot) = self.map.remove(&id)?;
        (slot.expires_at > now).then_some(slot.value)
    }

    /// Retira el slot solo si sigue siendo el que registro `nonce` (no uno posterior con el mismo ID).
    pub(crate) fn remove_matching(&self, id: u32, nonce: u64) -> bool {
        self.map.remove_if(&id, |_, s| s.nonce == nonce).is_some()
    }

    /// Elimina los slots vencidos y devuelve cuantos. Al soltar el valor, su dueno se entera.
    pub(crate) fn sweep(&self, now: Instant) -> usize {
        let mut removed = 0;
        self.map.retain(|_, slot| {
            let keep = slot.expires_at > now;
            if !keep {
                removed += 1;
            }
            keep
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const TTL: Duration = Duration::from_secs(600);

    fn table(max: usize) -> SlotTable<u8> {
        SlotTable::new(TTL, max)
    }

    #[test]
    fn insert_take_is_single_use() {
        let t0 = Instant::now();
        let t = table(8);
        t.insert(1, 7, t0).unwrap();
        assert_eq!(t.take(1, t0), Some(7));
        assert_eq!(t.take(1, t0), None);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn live_collision_is_rejected_and_keeps_the_first() {
        let t0 = Instant::now();
        let t = table(8);
        t.insert(1, 1, t0).unwrap();
        let later = t0 + Duration::from_secs(599);
        assert_eq!(t.insert(1, 2, later), Err(InsertError::Taken));
        assert_eq!(t.take(1, later), Some(1));
    }

    #[test]
    fn slot_expires_exactly_at_ttl() {
        let t0 = Instant::now();
        let t = table(8);
        t.insert(1, 1, t0).unwrap();
        assert_eq!(t.take(1, t0 + TTL - Duration::from_millis(1)), Some(1));
        t.insert(2, 2, t0).unwrap();
        assert_eq!(t.take(2, t0 + TTL), None);
        assert_eq!(t.len(), 0, "el slot vencido se descarta al consultarlo");
    }

    #[test]
    fn expired_slot_can_be_replaced() {
        let t0 = Instant::now();
        let t = table(8);
        let first = t.insert(1, 1, t0).unwrap();
        let second = t.insert(1, 2, t0 + TTL).unwrap();
        assert_ne!(first, second);
        assert_eq!(t.take(1, t0 + TTL), Some(2));
    }

    #[test]
    fn sweep_removes_only_expired_slots() {
        let t0 = Instant::now();
        let t = table(8);
        t.insert(1, 1, t0).unwrap();
        t.insert(2, 2, t0 + Duration::from_secs(300)).unwrap();
        assert_eq!(t.sweep(t0 + Duration::from_secs(599)), 0);
        assert_eq!(t.sweep(t0 + TTL), 1);
        assert_eq!(t.len(), 1);
        assert_eq!(t.take(2, t0 + TTL), Some(2));
    }

    #[test]
    fn full_table_rejects_new_ids() {
        let t0 = Instant::now();
        let t = table(2);
        t.insert(1, 1, t0).unwrap();
        t.insert(2, 2, t0).unwrap();
        assert_eq!(t.insert(3, 3, t0), Err(InsertError::Full));
        t.take(1, t0);
        t.insert(3, 3, t0).unwrap();
    }

    #[test]
    fn remove_matching_ignores_a_newer_registration() {
        let t0 = Instant::now();
        let t = table(8);
        let old = t.insert(1, 1, t0).unwrap();
        let new = t.insert(1, 2, t0 + TTL).unwrap();
        assert!(!t.remove_matching(1, old));
        assert_eq!(t.len(), 1);
        assert!(t.remove_matching(1, new));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn dropping_an_expired_value_notifies_its_owner() {
        let t0 = Instant::now();
        let t: SlotTable<Arc<()>> = SlotTable::new(TTL, 8);
        let witness = Arc::new(());
        t.insert(1, witness.clone(), t0).unwrap();
        assert_eq!(Arc::strong_count(&witness), 2);
        t.sweep(t0 + TTL);
        assert_eq!(Arc::strong_count(&witness), 1);
    }
}
