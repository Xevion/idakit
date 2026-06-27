//! [`Segment`]: a borrowed view of one segment, keyed by kernel index.

use crate::Idb;
use crate::ea::Ea;
use crate::ffi::read_string;

/// A borrowed view of one segment, valid while the database stays open.
#[derive(Clone, Copy)]
pub struct Segment<'db> {
    index: i32,
    db: &'db Idb,
}

impl<'db> Segment<'db> {
    #[inline]
    pub(crate) fn new(index: i32, db: &'db Idb) -> Self {
        Self { index, db }
    }

    /// The segment's kernel index.
    #[inline]
    #[must_use]
    pub const fn index(&self) -> i32 {
        self.index
    }

    /// The segment's name (e.g. `.text`), or `None` if unavailable.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        read_string(|buf, cap| self.db.seg_name(self.index, buf, cap))
    }

    /// First address of the segment.
    #[inline]
    #[must_use]
    pub fn start(&self) -> Option<Ea> {
        Ea::try_new(self.db.seg_start(self.index))
    }

    /// One-past-the-last address of the segment.
    #[inline]
    #[must_use]
    pub fn end(&self) -> Option<Ea> {
        Ea::try_new(self.db.seg_end(self.index))
    }

    /// The whole segment's bytes (`[start, end)`), or `None` if bounds are absent.
    #[must_use]
    pub fn bytes(&self) -> Option<Vec<u8>> {
        let (start, end) = (self.start()?, self.end()?);
        let len = (end - start).max(0) as usize;
        Some(self.db.bytes(start, len))
    }
}

impl std::fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("index", &self.index)
            .field("name", &self.name())
            .field("start", &self.start())
            .field("end", &self.end())
            .finish()
    }
}

// Identity is the kernel index alone; the `db` borrow is incidental and must not
// participate, so these are hand-written rather than derived.
impl PartialEq for Segment<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.index == o.index
    }
}
impl Eq for Segment<'_> {}
impl std::hash::Hash for Segment<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.index.hash(s);
    }
}
impl Ord for Segment<'_> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.index.cmp(&o.index)
    }
}
impl PartialOrd for Segment<'_> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// Lazy iterator over every segment in the database, in kernel order.
pub struct Segments<'db> {
    db: &'db Idb,
    next: i32,
    count: i32,
}

impl<'db> Segments<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Idb) -> Self {
        Self {
            db,
            next: 0,
            count: db.seg_qty(),
        }
    }
}

impl<'db> Iterator for Segments<'db> {
    type Item = Segment<'db>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.count {
            return None;
        }
        let seg = Segment::new(self.next, self.db);
        self.next += 1;
        Some(seg)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = (self.count - self.next).max(0) as usize;
        (rem, Some(rem))
    }
}

impl ExactSizeIterator for Segments<'_> {}
