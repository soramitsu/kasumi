use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
struct Fence(Arc<AtomicBool>);
impl Drop for Fence { fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); } }
fn main() {
    let released = Arc::new(AtomicBool::new(false));
    {
        let attempted = Ok::<_, ()>((String::from("receipt"), Fence(released.clone())));
        let receipt = match attempted { Ok((receipt, _)) => receipt, Err(()) => unreachable!() };
        assert!(!released.load(Ordering::SeqCst));
        drop(receipt);
        assert!(!released.load(Ordering::SeqCst));
    }
    assert!(released.load(Ordering::SeqCst));
    println!("Wildcard partial move retains the response fence until attempted leaves scope");
}
