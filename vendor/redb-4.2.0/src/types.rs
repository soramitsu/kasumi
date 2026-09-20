use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::convert::TryInto;
use core::fmt::Debug;
use core::mem::size_of;
#[cfg(feature = "chrono_v0_4")]
mod chrono_v0_4;
#[cfg(feature = "uuid")]
mod uuid;

#[derive(Eq, PartialEq, Clone, Debug)]
enum TypeClassification {
    Internal,
    UserDefined,
    // Retained only to report unsupported input; no canonical type uses this tag.
    Unsupported(u8),
    // Used by composite types written by version 4.2 and newer
    Internal3,
}

impl TypeClassification {
    fn to_byte(&self) -> u8 {
        match self {
            TypeClassification::Internal => 1,
            TypeClassification::UserDefined => 2,
            TypeClassification::Unsupported(tag) => *tag,
            TypeClassification::Internal3 => 4,
        }
    }

    fn from_byte(value: u8) -> Self {
        match value {
            1 => TypeClassification::Internal,
            2 => TypeClassification::UserDefined,
            4 => TypeClassification::Internal3,
            tag => TypeClassification::Unsupported(tag),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TypeName {
    classification: TypeClassification,
    name: String,
}

impl TypeName {
    /// It is recommended that `name` be prefixed with the crate name to minimize the chance of
    /// it coliding with another user defined type
    pub fn new(name: &str) -> Self {
        Self {
            classification: TypeClassification::UserDefined,
            name: name.to_string(),
        }
    }

    pub(crate) fn internal(name: &str) -> Self {
        Self {
            classification: TypeClassification::Internal,
            name: name.to_string(),
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.name.len() + 1);
        result.push(self.classification.to_byte());
        result.extend_from_slice(self.name.as_bytes());
        result
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let classification = TypeClassification::from_byte(bytes[0]);
        let name = core::str::from_utf8(&bytes[1..]).unwrap().to_string();

        Self {
            classification,
            name,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn is_user_defined(&self) -> bool {
        matches!(self.classification, TypeClassification::UserDefined)
    }

    pub(crate) fn is_supported(&self) -> bool {
        !matches!(self.classification, TypeClassification::Unsupported(_))
    }

    // The current writer emits only the exact composite identity; no earlier
    // classification is recorded or accepted as an alias.
    pub(crate) fn into_composite(mut self, user_defined: bool) -> Self {
        debug_assert!(matches!(self.classification, TypeClassification::Internal));
        self.classification = if user_defined {
            TypeClassification::UserDefined
        } else {
            TypeClassification::Internal3
        };
        self
    }
}

/// Types that implement this trait can be used as values in a redb table
pub trait Value: Debug {
    /// `SelfType<'a>` must be the same type as Self with all lifetimes replaced with 'a
    type SelfType<'a>: Debug + 'a
    where
        Self: 'a;

    type AsBytes<'a>: AsRef<[u8]> + 'a
    where
        Self: 'a;

    /// Width of a fixed type, or None for variable width
    fn fixed_width() -> Option<usize>;

    /// Deserializes data
    /// Implementations may return a view over data, or an owned type
    ///
    /// Note: Implementations may assume that `data` is the return value of `as_bytes(&v)` for some `v` of type `Self`.
    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a;

    /// Serialize the value to a slice
    ///
    /// Note: Implementations must ensure that `as_bytes()` and `from_bytes()` are inverses.
    /// Specifically, for any value `v` and `data` returned from `as_bytes(&v)`,
    /// `as_bytes(from_bytes(data))` must equal `data`.
    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b;

    /// Globally unique identifier for this type
    fn type_name() -> TypeName;
}

/// Implementing this trait indicates that the type can be mutated in-place as a &mut [u8].
/// This enables the `.insert_reserve()` method on Table
pub trait MutInPlaceValue: Value {
    /// The base type such that &mut [u8] can be safely transmuted to `&mut BaseRefType`
    type BaseRefType: Debug + ?Sized;

    /// Initialize `data` to a valid value. This method will be called (at some point, not necessarily immediately)
    /// before `from_bytes_mut()` is called on a slice.
    ///
    /// Note: There must exist a value `v` of type `Self` such that `as_bytes(&v)` equals `data`.
    fn initialize(data: &mut [u8]);

    fn from_bytes_mut(data: &mut [u8]) -> &mut Self::BaseRefType;
}

impl MutInPlaceValue for &[u8] {
    type BaseRefType = [u8];

    fn initialize(_data: &mut [u8]) {
        // no-op. All values are valid.
    }

    fn from_bytes_mut(data: &mut [u8]) -> &mut Self::BaseRefType {
        data
    }
}

/// Trait which allows the type to be used as a key in a redb table
pub trait Key: Value {
    /// Compare data1 with data2.
    ///
    /// The implementation must ensure there is a total order
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering;
}

impl Value for () {
    type SelfType<'a>
        = ()
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        Some(0)
    }

    #[allow(clippy::unused_unit, clippy::semicolon_if_nothing_returned)]
    fn from_bytes<'a>(_data: &'a [u8]) -> ()
    where
        Self: 'a,
    {
        ()
    }

    #[allow(clippy::ignored_unit_patterns)]
    fn as_bytes<'a, 'b: 'a>(_: &'a Self::SelfType<'b>) -> &'a [u8]
    where
        Self: 'b,
    {
        &[]
    }

    fn type_name() -> TypeName {
        TypeName::internal("()")
    }
}

impl Key for () {
    fn compare(_data1: &[u8], _data2: &[u8]) -> Ordering {
        Ordering::Equal
    }
}

impl Value for bool {
    type SelfType<'a>
        = bool
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        Some(1)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> bool
    where
        Self: 'a,
    {
        match data[0] {
            0 => false,
            1 => true,
            _ => unreachable!(),
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> &'a [u8]
    where
        Self: 'b,
    {
        match value {
            true => &[1],
            false => &[0],
        }
    }

    fn type_name() -> TypeName {
        TypeName::internal("bool")
    }
}

impl Key for bool {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        let value1 = Self::from_bytes(data1);
        let value2 = Self::from_bytes(data2);
        value1.cmp(&value2)
    }
}

impl<T: Value> Value for Option<T> {
    type SelfType<'a>
        = Option<T::SelfType<'a>>
    where
        Self: 'a;
    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        T::fixed_width().map(|x| x + 1)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Option<T::SelfType<'a>>
    where
        Self: 'a,
    {
        match data[0] {
            0 => None,
            1 => Some(T::from_bytes(&data[1..])),
            _ => unreachable!(),
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Vec<u8>
    where
        Self: 'b,
    {
        let mut result = vec![0];
        if let Some(x) = value {
            result[0] = 1;
            result.extend_from_slice(T::as_bytes(x).as_ref());
        } else if let Some(fixed_width) = T::fixed_width() {
            result.extend_from_slice(&vec![0; fixed_width]);
        }
        result
    }

    fn type_name() -> TypeName {
        let inner = T::type_name();
        TypeName::internal(&format!("Option<{}>", inner.name()))
            .into_composite(inner.is_user_defined())
    }
}

impl<T: Key> Key for Option<T> {
    #[allow(clippy::collapsible_else_if)]
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        if data1[0] == 0 {
            if data2[0] == 0 {
                Ordering::Equal
            } else {
                Ordering::Less
            }
        } else {
            if data2[0] == 0 {
                Ordering::Greater
            } else {
                T::compare(&data1[1..], &data2[1..])
            }
        }
    }
}

impl Value for &[u8] {
    type SelfType<'a>
        = &'a [u8]
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> &'a [u8]
    where
        Self: 'a,
    {
        data
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> &'a [u8]
    where
        Self: 'b,
    {
        value
    }

    fn type_name() -> TypeName {
        TypeName::internal("&[u8]")
    }
}

impl Key for &[u8] {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        data1.cmp(data2)
    }
}

impl<const N: usize> Value for &[u8; N] {
    type SelfType<'a>
        = &'a [u8; N]
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8; N]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        Some(N)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> &'a [u8; N]
    where
        Self: 'a,
    {
        data.try_into().unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> &'a [u8; N]
    where
        Self: 'b,
    {
        value
    }

    fn type_name() -> TypeName {
        TypeName::internal(&format!("[u8;{N}]")).into_composite(false)
    }
}

impl<const N: usize> Key for &[u8; N] {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        data1.cmp(data2)
    }
}

impl<const N: usize, T: Value> Value for [T; N] {
    type SelfType<'a>
        = [T::SelfType<'a>; N]
    where
        Self: 'a;
    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        T::fixed_width().map(|x| x * N)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> [T::SelfType<'a>; N]
    where
        Self: 'a,
    {
        let mut result = Vec::with_capacity(N);
        if let Some(fixed) = T::fixed_width() {
            for i in 0..N {
                result.push(T::from_bytes(&data[fixed * i..fixed * (i + 1)]));
            }
        } else {
            // Set offset to the first data item
            let mut start = size_of::<u32>() * N;
            for i in 0..N {
                let range = size_of::<u32>() * i..size_of::<u32>() * (i + 1);
                let end = u32::from_le_bytes(data[range].try_into().unwrap()) as usize;
                result.push(T::from_bytes(&data[start..end]));
                start = end;
            }
        }
        result.try_into().unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Vec<u8>
    where
        Self: 'b,
    {
        if let Some(fixed) = T::fixed_width() {
            let mut result = Vec::with_capacity(fixed * N);
            for item in value {
                result.extend_from_slice(T::as_bytes(item).as_ref());
            }
            result
        } else {
            // Reserve space for the end offsets
            let mut result = vec![0u8; size_of::<u32>() * N];
            for i in 0..N {
                result.extend_from_slice(T::as_bytes(&value[i]).as_ref());
                let end: u32 = result.len().try_into().unwrap();
                result[size_of::<u32>() * i..size_of::<u32>() * (i + 1)]
                    .copy_from_slice(&end.to_le_bytes());
            }
            result
        }
    }

    fn type_name() -> TypeName {
        // Uses the same type name as [T;N] so that tables are compatible with [u8;N] and &[u8;N] types
        // This requires that the binary encoding be the same
        let inner = T::type_name();
        TypeName::internal(&format!("[{};{N}]", inner.name()))
            .into_composite(inner.is_user_defined())
    }
}

impl<const N: usize, T: Key> Key for [T; N] {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        if let Some(fixed) = T::fixed_width() {
            for i in 0..N {
                let range = fixed * i..fixed * (i + 1);
                let comparison = T::compare(&data1[range.clone()], &data2[range]);
                if !comparison.is_eq() {
                    return comparison;
                }
            }
        } else {
            // Set offset to the first data item
            let mut start1 = size_of::<u32>() * N;
            let mut start2 = size_of::<u32>() * N;
            for i in 0..N {
                let range = size_of::<u32>() * i..size_of::<u32>() * (i + 1);
                let end1 = u32::from_le_bytes(data1[range.clone()].try_into().unwrap()) as usize;
                let end2 = u32::from_le_bytes(data2[range].try_into().unwrap()) as usize;
                let comparison = T::compare(&data1[start1..end1], &data2[start2..end2]);
                if !comparison.is_eq() {
                    return comparison;
                }
                start1 = end1;
                start2 = end2;
            }
        }
        Ordering::Equal
    }
}

impl Value for &str {
    type SelfType<'a>
        = &'a str
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a str
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> &'a str
    where
        Self: 'a,
    {
        core::str::from_utf8(data).unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> &'a str
    where
        Self: 'b,
    {
        value
    }

    fn type_name() -> TypeName {
        TypeName::internal("&str")
    }
}

impl Key for &str {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        let str1 = Self::from_bytes(data1);
        let str2 = Self::from_bytes(data2);
        str1.cmp(str2)
    }
}

impl Value for String {
    type SelfType<'a>
        = String
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a str
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> String
    where
        Self: 'a,
    {
        core::str::from_utf8(data).unwrap().to_string()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> &'a str
    where
        Self: 'b,
    {
        value.as_str()
    }

    fn type_name() -> TypeName {
        TypeName::internal("String")
    }
}

impl Key for String {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        let str1 = core::str::from_utf8(data1).unwrap();
        let str2 = core::str::from_utf8(data2).unwrap();
        str1.cmp(str2)
    }
}

impl Value for char {
    type SelfType<'a> = char;
    type AsBytes<'a>
        = [u8; 3]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        Some(3)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> char
    where
        Self: 'a,
    {
        char::from_u32(u32::from_le_bytes([data[0], data[1], data[2], 0])).unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> [u8; 3]
    where
        Self: 'b,
    {
        let bytes = u32::from(*value).to_le_bytes();
        [bytes[0], bytes[1], bytes[2]]
    }

    fn type_name() -> TypeName {
        TypeName::internal(stringify!(char))
    }
}

impl Key for char {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        Self::from_bytes(data1).cmp(&Self::from_bytes(data2))
    }
}

macro_rules! le_value {
    ($t:ty) => {
        impl Value for $t {
            type SelfType<'a> = $t;
            type AsBytes<'a>
                = [u8; core::mem::size_of::<$t>()]
            where
                Self: 'a;

            fn fixed_width() -> Option<usize> {
                Some(core::mem::size_of::<$t>())
            }

            fn from_bytes<'a>(data: &'a [u8]) -> $t
            where
                Self: 'a,
            {
                <$t>::from_le_bytes(data.try_into().unwrap())
            }

            fn as_bytes<'a, 'b: 'a>(
                value: &'a Self::SelfType<'b>,
            ) -> [u8; core::mem::size_of::<$t>()]
            where
                Self: 'a,
                Self: 'b,
            {
                value.to_le_bytes()
            }

            fn type_name() -> TypeName {
                TypeName::internal(stringify!($t))
            }
        }
    };
}

macro_rules! le_impl {
    ($t:ty) => {
        le_value!($t);

        impl Key for $t {
            fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
                Self::from_bytes(data1).cmp(&Self::from_bytes(data2))
            }
        }
    };
}

le_impl!(u8);
le_impl!(u16);
le_impl!(u32);
le_impl!(u64);
le_impl!(u128);
le_impl!(i8);
le_impl!(i16);
le_impl!(i32);
le_impl!(i64);
le_impl!(i128);
le_value!(f32);
le_value!(f64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_is_readable_through_reconstruction() {
        // The derive macro reads a field type's classification by rebuilding its `TypeName`
        // through `TypeName::new` and comparing, because the generated code has to compile
        // against older redb versions that lack `is_user_defined()` (see `#[redb(crate)]` in
        // redb-derive). Equality must keep agreeing with `is_user_defined()` for every
        // classification.
        let samples = [
            TypeName::new("Plain"),
            TypeName::internal("Plain"),
            TypeName::internal("Composite").into_composite(true),
            TypeName::internal("Composite").into_composite(false),
        ];
        for type_name in samples {
            assert_eq!(
                type_name.is_user_defined(),
                type_name == TypeName::new(type_name.name())
            );
        }
    }

    // A user-defined type whose name deliberately collides with the built-in `u32`, and whose
    // fixed width matches it. Before composite classifications bubbled up, `Option<FakeU32>` and
    // `Option<u32>` produced byte-identical `TypeName`s, letting one silently open as the other.
    #[derive(Debug)]
    struct FakeU32;

    impl Value for FakeU32 {
        type SelfType<'a> = u32;
        type AsBytes<'a> = [u8; 4];

        fn fixed_width() -> Option<usize> {
            Some(4)
        }

        fn from_bytes<'a>(data: &'a [u8]) -> u32
        where
            Self: 'a,
        {
            u32::from_le_bytes(data.try_into().unwrap())
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a u32) -> [u8; 4]
        where
            Self: 'b,
        {
            value.to_le_bytes()
        }

        fn type_name() -> TypeName {
            TypeName::new("u32")
        }
    }

    impl Key for FakeU32 {
        fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
            data1.cmp(data2)
        }
    }

    #[test]
    fn builtin_composites_use_only_canonical_classification() {
        fn assert_internal3(name: TypeName) {
            assert!(matches!(name.classification, TypeClassification::Internal3));
        }

        assert_internal3(<Option<u32> as Value>::type_name());
        assert_internal3(<Vec<u32> as Value>::type_name());
        assert_internal3(<[u32; 3] as Value>::type_name());
        assert_internal3(<&[u8; 3] as Value>::type_name());
        assert_internal3(<(u32,) as Value>::type_name());
        assert_internal3(<(u32, u64) as Value>::type_name());
        assert_internal3(<(u32, &str) as Value>::type_name());
        assert_internal3(<Vec<Option<u32>> as Value>::type_name());

        // The owned and borrowed byte-array types remain compatible.
        assert_eq!(
            <[u8; 3] as Value>::type_name(),
            <&[u8; 3] as Value>::type_name()
        );

        assert_ne!(
            <Option<u32> as Value>::type_name(),
            TypeName::internal("Option<u32>")
        );
        assert_ne!(
            <(u32, u64) as Value>::type_name(),
            TypeName::internal("(u32,u64)")
        );
        let old_variable_tuple = TypeName::from_bytes(b"\x03(u32,&str)");
        assert!(!old_variable_tuple.is_supported());
        assert_ne!(<(u32, &str) as Value>::type_name(), old_variable_tuple);
    }

    #[test]
    fn composite_of_user_type_no_longer_collides_with_builtin() {
        // The bug: these pairs were equal before the fix.
        assert_ne!(
            <Option<u32> as Value>::type_name(),
            <Option<FakeU32> as Value>::type_name()
        );
        assert_ne!(
            <Vec<u32> as Value>::type_name(),
            <Vec<FakeU32> as Value>::type_name()
        );
        assert_ne!(
            <[u32; 2] as Value>::type_name(),
            <[FakeU32; 2] as Value>::type_name()
        );
        assert_ne!(
            <(u32, u64) as Value>::type_name(),
            <(FakeU32, u64) as Value>::type_name()
        );
        assert_ne!(
            <(u32, &str) as Value>::type_name(),
            <(FakeU32, &str) as Value>::type_name()
        );

        // Only the classification differs; the human-readable name string is unchanged, and the
        // user composite is classified user-defined.
        assert_eq!(
            <Option<u32> as Value>::type_name().name(),
            <Option<FakeU32> as Value>::type_name().name()
        );
        assert!(<Option<FakeU32> as Value>::type_name().is_user_defined());
        // Bubbling is transitive through nesting.
        assert!(<Vec<Option<FakeU32>> as Value>::type_name().is_user_defined());
    }

    #[test]
    fn legacy_composite_names_never_match_canonical_types() {
        assert_ne!(
            <Option<FakeU32> as Value>::type_name(),
            TypeName::internal("Option<u32>")
        );
        assert_ne!(
            <Vec<FakeU32> as Value>::type_name(),
            TypeName::internal("Vec<u32>")
        );
        assert_ne!(
            <(FakeU32,) as Value>::type_name(),
            TypeName::internal("(u32,)")
        );
        assert_ne!(
            <(FakeU32, u64) as Value>::type_name(),
            TypeName::internal("(u32,u64)")
        );
        assert_ne!(
            <(FakeU32, &str) as Value>::type_name(),
            TypeName::from_bytes(b"\x03(u32,&str)")
        );
        assert_ne!(<FakeU32 as Value>::type_name(), TypeName::internal("u32"));
    }
}
