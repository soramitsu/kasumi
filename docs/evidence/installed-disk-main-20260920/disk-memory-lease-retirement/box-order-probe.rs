use std::{alloc::{GlobalAlloc, Layout, System}, sync::atomic::{AtomicBool, AtomicUsize, Ordering}};
struct Observed;
static WATCH: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATED: AtomicBool = AtomicBool::new(false);
static DROP_SAW_DEALLOCATED: AtomicBool = AtomicBool::new(false);
#[global_allocator]
static ALLOCATOR: Observed = Observed;
unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 { unsafe { System.alloc(layout) } }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let observed = WATCH.compare_exchange(pointer as usize, 0, Ordering::AcqRel, Ordering::Acquire).is_ok();
        unsafe { System.dealloc(pointer, layout) };
        if observed { DEALLOCATED.store(true, Ordering::Release); }
    }
}
struct Payload([u8; 64]);
impl Drop for Payload {
    fn drop(&mut self) {
        DROP_SAW_DEALLOCATED.store(DEALLOCATED.load(Ordering::Acquire), Ordering::Release);
        std::hint::black_box(self.0[0]);
    }
}
trait Named { fn retire(self: Box<Self>); }
impl Named for Payload { fn retire(self: Box<Self>) { let value = *self; drop(value); } }
trait Helper { fn retire(self: Box<Self>); }
fn unbox<T>(value: Box<T>) -> T { *value }
impl Helper for Payload { fn retire(self: Box<Self>) { drop(unbox(self)); } }
trait Scoped { fn retire(self: Box<Self>); }
impl Scoped for Payload { fn retire(self: Box<Self>) { let value = { let allocation = self; *allocation }; drop(value); } }
fn arm<T>(value: &T) { DEALLOCATED.store(false, Ordering::Release); DROP_SAW_DEALLOCATED.store(false, Ordering::Release); WATCH.store(std::ptr::from_ref(value) as usize, Ordering::Release); }
fn result(name: &str, expected: bool) { let observed=DROP_SAW_DEALLOCATED.load(Ordering::Acquire); assert!(DEALLOCATED.load(Ordering::Acquire)); println!("{name}: payload Drop observed actual System.dealloc completion = {observed}"); assert_eq!(observed,expected); }
struct Entry { value: Payload, next: Option<Box<Entry>> }
fn remove(cursor: &mut Option<Box<Entry>>) -> Option<Payload> { let Entry {value,next}=*cursor.take()?; *cursor=next; Some(value) }
fn main() {
 let value=Box::new(Payload([0;64])); arm(&*value); let erased:Box<dyn Named>=value; erased.retire(); result("named-self-local",false);
 let value=Box::new(Payload([0;64])); arm(&*value); let erased:Box<dyn Helper>=value; erased.retire(); result("consuming-helper",true);
 let value=Box::new(Payload([0;64])); arm(&*value); let erased:Box<dyn Scoped>=value; erased.retire(); result("explicit-inner-scope",true);
 let value=Box::new(Entry{value:Payload([0;64]),next:None}); arm(&*value); let mut slot=Some(value); drop(remove(&mut slot)); result("list-remove-temporary",true);
 println!("pointer widths: Box<dyn Named>={} Option<Box<dyn Named>>={} align={} option-align={}",std::mem::size_of::<Box<dyn Named>>(),std::mem::size_of::<Option<Box<dyn Named>>>(),std::mem::align_of::<Box<dyn Named>>(),std::mem::align_of::<Option<Box<dyn Named>>>());
}
