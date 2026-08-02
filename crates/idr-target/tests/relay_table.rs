use idr_target::relay::descriptor::{hash_relay_id, GenerationalHandle};
use idr_target::relay::table::RelayConnectionTable;

#[test]
fn table_insert_collision_probe() {
    let mut table = RelayConnectionTable::with_capacity(1024);
    for i in 0..64 {
        let id = format!("relay-{i}");
        let h = GenerationalHandle::encode(i, 2);
        table.insert_slot(id, h);
    }
    for i in 0..64 {
        assert!(table.lookup_slot(&format!("relay-{i}")).is_some());
    }
}

#[test]
fn hash_mixed_not_low_bits_only() {
    let a = hash_relay_id("relay-a");
    let b = hash_relay_id("relay-b");
    assert_ne!(a, b);
    assert_ne!(a & 0xFFF, b & 0xFFF);
}
