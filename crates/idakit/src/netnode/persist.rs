//! The [`Persist`] trait: values that round-trip through a netnode's byte storage.

/// A value that can be stored in and read back from a netnode.
///
/// Backs the typed key/value store ([`put`](super::NetnodeMut::put) /
/// [`get`](super::Netnode::get)), which writes the serialized bytes into the hash under a string
/// key. idakit implements it for the native scalar, boolean, string, and byte-vector types; a
/// `serde`-backed encoding can layer on later behind a feature.
///
/// ```
/// use idakit::netnode::Persist;
/// assert_eq!(u64::from_netnode_bytes(&42u64.to_netnode_bytes()), Some(42));
/// assert_eq!(u32::from_netnode_bytes(&[1, 2, 3]), None); // wrong width
/// ```
pub trait Persist: Sized {
    /// Serialize to the bytes stored in the netnode.
    #[must_use]
    fn to_netnode_bytes(&self) -> Vec<u8>;

    /// Reconstruct from stored bytes, or `None` if they do not decode as `Self`.
    #[must_use]
    fn from_netnode_bytes(bytes: &[u8]) -> Option<Self>;
}

/// Little-endian fixed-width round-trip for every native integer: decode fails unless the byte
/// count matches the type's width exactly.
macro_rules! impl_persist_le {
    ($($t:ty),*) => {$(
        impl Persist for $t {
            #[inline]
            fn to_netnode_bytes(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }
            #[inline]
            fn from_netnode_bytes(bytes: &[u8]) -> Option<Self> {
                bytes.try_into().ok().map(<$t>::from_le_bytes)
            }
        }
    )*};
}

impl_persist_le!(u8, u16, u32, u64, i8, i16, i32, i64);

impl Persist for bool {
    #[inline]
    fn to_netnode_bytes(&self) -> Vec<u8> {
        vec![u8::from(*self)]
    }
    #[inline]
    fn from_netnode_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [b] => Some(*b != 0),
            _ => None,
        }
    }
}

impl Persist for String {
    #[inline]
    fn to_netnode_bytes(&self) -> Vec<u8> {
        self.clone().into_bytes()
    }
    #[inline]
    fn from_netnode_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_utf8(bytes.to_vec()).ok()
    }
}

impl Persist for Vec<u8> {
    #[inline]
    fn to_netnode_bytes(&self) -> Vec<u8> {
        self.clone()
    }
    #[inline]
    fn from_netnode_bytes(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    fn roundtrips<T: Persist + PartialEq + std::fmt::Debug>(value: T) {
        let bytes = value.to_netnode_bytes();
        assert!(T::from_netnode_bytes(&bytes) == Some(value));
    }

    #[test]
    fn native_types_round_trip() {
        roundtrips(0u8);
        roundtrips(0xdead_beefu32);
        roundtrips(0x0123_4567_89ab_cdefu64);
        roundtrips(-1i64);
        roundtrips(true);
        roundtrips(false);
        roundtrips(String::from("idakit"));
        roundtrips(vec![1u8, 2, 3, 4]);
    }

    #[test]
    fn wrong_width_integer_rejects() {
        assert!(u64::from_netnode_bytes(&[1, 2, 3]) == None);
        assert!(bool::from_netnode_bytes(&[0, 1]) == None);
    }

    #[test]
    fn invalid_utf8_string_rejects() {
        assert!(String::from_netnode_bytes(&[0xff, 0xfe]) == None);
    }
}
