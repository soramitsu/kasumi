Prepared and unapplied; requires the new store NodeDiskMemoryAdmission trait.
Root owns this engine adapter and will add `mod disk_memory;` to admission.rs
when the combined store/core/caller layer is ready. The required byte helper
includes allocation_bytes::<Reservation>(1) before boxing the real core-owned
resident charge; it has no runtime-facade or operation-slot dependency.
Compilation, allocator/lifetime tests and installed caller qualification pending.
