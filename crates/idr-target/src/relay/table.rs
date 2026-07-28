use crate::relay::descriptor::{GenerationalHandle, RelayId, hash_relay_id};

pub const LOAD_FACTOR_MAX: f64 = 0.60;
pub const TOMBSTONE_REBUILD_RATIO: f64 = 0.15;

/// Open-addressing connection table keyed by relay_id with generational arena handles.
pub struct RelayConnectionTable {
    capacity: usize,
    slots: Vec<u64>,
    relay_ids: Vec<Option<RelayId>>,
    tombstones: usize,
    occupied: usize,
}

impl RelayConnectionTable {
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be power of two");
        Self {
            capacity,
            slots: vec![GenerationalHandle::EMPTY; capacity],
            relay_ids: vec![None; capacity],
            tombstones: 0,
            occupied: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn occupied(&self) -> usize {
        self.occupied
    }

    pub fn tombstones(&self) -> usize {
        self.tombstones
    }

    pub fn load_ratio(&self) -> f64 {
        (self.occupied + self.tombstones) as f64 / self.capacity as f64
    }

    pub fn tombstone_ratio(&self) -> f64 {
        self.tombstones as f64 / self.capacity as f64
    }

    pub fn needs_resize(&self) -> bool {
        self.load_ratio() > LOAD_FACTOR_MAX && self.capacity < usize::MAX / 2
    }

    pub fn needs_rebuild(&self) -> bool {
        self.tombstone_ratio() > TOMBSTONE_REBUILD_RATIO
    }

    pub fn probe_index(&self, relay_id: &str) -> usize {
        (hash_relay_id(relay_id) as usize) & (self.capacity - 1)
    }

    pub fn lookup_slot(&self, relay_id: &str) -> Option<(usize, GenerationalHandle)> {
        let mut idx = self.probe_index(relay_id);
        let mut probes = 0usize;
        loop {
            probes += 1;
            match self.slots[idx] {
                GenerationalHandle::EMPTY => return None,
                GenerationalHandle::TOMBSTONE => {}
                raw => {
                    if self.relay_ids[idx].as_deref() == Some(relay_id) {
                        return GenerationalHandle::from_raw(raw).map(|h| (idx, h));
                    }
                }
            }
            idx = (idx + 1) & (self.capacity - 1);
            if probes >= self.capacity {
                return None;
            }
        }
    }

    pub fn lookup_probes(&self, relay_id: &str) -> (Option<(usize, GenerationalHandle)>, usize) {
        let start = self.probe_index(relay_id);
        let mut idx = start;
        let mut probes = 0usize;
        loop {
            probes += 1;
            match self.slots[idx] {
                GenerationalHandle::EMPTY => return (None, probes),
                GenerationalHandle::TOMBSTONE => {}
                raw => {
                    if self.relay_ids[idx].as_deref() == Some(relay_id) {
                        if let Some(h) = GenerationalHandle::from_raw(raw) {
                            return (Some((idx, h)), probes);
                        }
                    }
                }
            }
            idx = (idx + 1) & (self.capacity - 1);
            if probes >= self.capacity {
                return (None, probes);
            }
        }
    }

    pub fn insert_slot(&mut self, relay_id: RelayId, handle: GenerationalHandle) -> usize {
        if self.needs_resize() {
            self.resize(self.capacity * 2);
        } else if self.needs_rebuild() {
            self.rebuild();
        }

        let mut idx = self.probe_index(&relay_id);
        let mut first_tombstone: Option<usize> = None;
        let mut probes = 0usize;
        loop {
            probes += 1;
            match self.slots[idx] {
                GenerationalHandle::EMPTY => {
                    let slot = first_tombstone.unwrap_or(idx);
                    if first_tombstone.is_some() {
                        self.tombstones = self.tombstones.saturating_sub(1);
                    }
                    self.slots[slot] = handle.raw();
                    self.relay_ids[slot] = Some(relay_id);
                    self.occupied += 1;
                    return slot;
                }
                GenerationalHandle::TOMBSTONE => {
                    if first_tombstone.is_none() {
                        first_tombstone = Some(idx);
                    }
                }
                _ => {
                    if self.relay_ids[idx].as_deref() == Some(relay_id.as_str()) {
                        self.slots[idx] = handle.raw();
                        self.relay_ids[idx] = Some(relay_id);
                        return idx;
                    }
                }
            }
            idx = (idx + 1) & (self.capacity - 1);
            if probes >= self.capacity {
                panic!("relay connection table insert failed: table full");
            }
        }
    }

    pub fn remove_slot(&mut self, relay_id: &str) -> bool {
        let Some((idx, _)) = self.lookup_slot(relay_id) else {
            return false;
        };
        self.slots[idx] = GenerationalHandle::TOMBSTONE;
        self.relay_ids[idx] = None;
        self.occupied = self.occupied.saturating_sub(1);
        self.tombstones += 1;
        true
    }

    pub fn update_handle(&mut self, relay_id: &str, handle: GenerationalHandle) -> bool {
        if let Some((idx, _)) = self.lookup_slot(relay_id) {
            self.slots[idx] = handle.raw();
            true
        } else {
            false
        }
    }

    fn rebuild(&mut self) {
        let old_capacity = self.capacity;
        let old_slots = std::mem::replace(&mut self.slots, vec![GenerationalHandle::EMPTY; old_capacity]);
        let old_ids = std::mem::replace(&mut self.relay_ids, vec![None; old_capacity]);
        self.tombstones = 0;
        self.occupied = 0;
        for (slot, id) in old_slots.into_iter().zip(old_ids.into_iter()) {
            if slot > GenerationalHandle::TOMBSTONE {
                if let (Some(handle), Some(relay_id)) = (GenerationalHandle::from_raw(slot), id) {
                    self.insert_slot(relay_id, handle);
                }
            }
        }
    }

    fn resize(&mut self, new_capacity: usize) {
        let mut entries = Vec::new();
        for (slot, id) in self.slots.drain(..).zip(self.relay_ids.drain(..)) {
            if slot > GenerationalHandle::TOMBSTONE {
                if let (Some(handle), Some(relay_id)) = (GenerationalHandle::from_raw(slot), id) {
                    entries.push((relay_id, handle));
                }
            }
        }
        self.capacity = new_capacity;
        self.slots = vec![GenerationalHandle::EMPTY; new_capacity];
        self.relay_ids = vec![None; new_capacity];
        self.tombstones = 0;
        self.occupied = 0;
        for (relay_id, handle) in entries {
            self.insert_slot(relay_id, handle);
        }
    }

    pub fn iter_active_relay_ids(&self) -> impl Iterator<Item = &str> {
        self.relay_ids
            .iter()
            .filter_map(|id| id.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_lookup_remove() {
        let mut table = RelayConnectionTable::with_capacity(1024);
        let h = GenerationalHandle::encode(0, 2);
        table.insert_slot("relay-a".into(), h);
        let found = table.lookup_slot("relay-a");
        assert!(found.is_some());
        assert!(table.remove_slot("relay-a"));
        assert!(table.lookup_slot("relay-a").is_none());
    }

    #[test]
    fn collision_distinct_ids() {
        let mut table = RelayConnectionTable::with_capacity(16);
        for i in 0..8 {
            let h = GenerationalHandle::encode(i, 2);
            table.insert_slot(format!("relay-{i}"), h);
        }
        for i in 0..8 {
            assert!(table.lookup_slot(&format!("relay-{i}")).is_some());
        }
    }
}
