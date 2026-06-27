//! [`Func`]: a borrowed view of one function, keyed by its entry [`Ea`].

use crate::Idb;
use crate::decompile::Cfunc;
use crate::ea::Ea;
use crate::error::Result;
use crate::ffi::read_string;
use crate::xref::Xref;

/// A borrowed view of one function, valid while the database stays open.
#[derive(Clone, Copy)]
pub struct Func<'db> {
    ea: Ea,
    db: &'db Idb,
}

impl<'db> Func<'db> {
    #[inline]
    pub(crate) fn new(ea: Ea, db: &'db Idb) -> Self {
        Self { ea, db }
    }

    /// The function's entry address.
    #[inline]
    #[must_use]
    pub const fn ea(&self) -> Ea {
        self.ea
    }

    /// The function's display name, or `None` if unavailable.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        read_string(|buf, cap| self.db.func_name(self.ea, buf, cap))
    }

    /// The one-line C prototype, or `None` if the kernel has no type info.
    #[must_use]
    pub fn prototype(&self) -> Option<String> {
        read_string(|buf, cap| self.db.func_type(self.ea, buf, cap))
    }

    /// All cross-references targeting this function's entry.
    #[must_use]
    pub fn xrefs_to(&self) -> Vec<Xref> {
        self.db.xrefs_to(self.ea)
    }

    /// Decompile this function.
    pub fn decompile(&self) -> Result<Cfunc<'db>> {
        self.db.decompile(self.ea)
    }
}

impl std::fmt::Debug for Func<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Func")
            .field("ea", &self.ea)
            .field("name", &self.name())
            .finish()
    }
}

// Identity is the entry address alone; the `db` borrow is incidental and must not
// participate, so these are hand-written rather than derived.
impl PartialEq for Func<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.ea == o.ea
    }
}
impl Eq for Func<'_> {}
impl std::hash::Hash for Func<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.ea.hash(s);
    }
}
impl Ord for Func<'_> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.ea.cmp(&o.ea)
    }
}
impl PartialOrd for Func<'_> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// Lazy iterator over every function in the database, in kernel order.
pub struct Functions<'db> {
    db: &'db Idb,
    next: usize,
    count: usize,
}

impl<'db> Functions<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Idb) -> Self {
        Self {
            db,
            next: 0,
            count: db.func_qty(),
        }
    }
}

impl<'db> Iterator for Functions<'db> {
    type Item = Func<'db>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.count {
            let raw = self.db.func_ea(self.next);
            self.next += 1;
            if let Some(ea) = Ea::try_new(raw) {
                return Some(Func::new(ea, self.db));
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.count - self.next))
    }
}
