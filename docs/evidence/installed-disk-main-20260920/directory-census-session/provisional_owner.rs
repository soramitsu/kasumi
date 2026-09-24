/// Private, unique Arc custody until registry publication. On error/unwind the
/// Arc allocation itself retires before its value and resident lease can drop.
struct ProvisionalOwner<T>(Option<Arc<T>>);
impl<T> ProvisionalOwner<T> {
    fn new(value: T) -> Self { Self(Some(Arc::new(value))) }
}
impl<T> std::ops::Deref for ProvisionalOwner<T> {
    type Target = T;
    fn deref(&self) -> &T { self.0.as_deref().expect("private provisional owner") }
}
impl<T> Drop for ProvisionalOwner<T> {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            // No Arc or Weak escapes before publication. into_inner retires
            // the strong/implicit-weak backing before returning the owned T.
            let value = Arc::into_inner(owner).expect("unique provisional Arc");
            drop(value);
        }
    }
}
impl ProvisionalOwner<NodeDisk> {
    fn install(mut self, registration: &mut PreparingRegistration<'_>) -> Arc<NodeDisk> {
        // Keep private custody until the retained registry clone is installed.
        // There is no fallible operation between that installation and take.
        registration.commit(self.0.as_ref().expect("provisional owner").clone());
        self.0.take().expect("registered owner")
    }
}
