//! Fixed-capacity containers.
//!
//! The protocol core forbids heap allocation; every collection in the core is
//! one of these bounded structures so worst-case memory is a compile-time
//! constant (certification requirement; see PLAN.md "Memory Model").

/// A fixed-capacity vector of `Copy` elements.
///
/// `push` reports failure instead of allocating; callers must decide the
/// overflow policy explicitly (drop, replace, or treat as protocol error).
#[derive(Debug, Clone, Copy)]
pub struct BoundedVec<T: Copy, const N: usize> {
    items: [T; N],
    len: usize,
}

impl<T: Copy + Default, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> BoundedVec<T, N> {
    /// An empty vector.
    pub fn new() -> Self {
        BoundedVec {
            items: [T::default(); N],
            len: 0,
        }
    }
}

impl<T: Copy, const N: usize> BoundedVec<T, N> {
    /// Number of elements currently stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no elements are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True if at capacity.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// Append an element. Returns `Err(value)` when full.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.len < N {
            self.items[self.len] = value;
            self.len += 1;
            Ok(())
        } else {
            Err(value)
        }
    }

    /// Insert at `idx`, shifting later elements right. Returns `Err(value)`
    /// when full or `idx > len`.
    pub fn insert(&mut self, idx: usize, value: T) -> Result<(), T> {
        if self.len >= N || idx > self.len {
            return Err(value);
        }
        let mut i = self.len;
        while i > idx {
            self.items[i] = self.items[i - 1];
            i -= 1;
        }
        self.items[idx] = value;
        self.len += 1;
        Ok(())
    }

    /// Remove and return the element at `idx`, shifting later elements left.
    pub fn remove(&mut self, idx: usize) -> Option<T> {
        if idx >= self.len {
            return None;
        }
        let value = self.items[idx];
        for i in idx..self.len - 1 {
            self.items[i] = self.items[i + 1];
        }
        self.len -= 1;
        Some(value)
    }

    /// Remove all elements.
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Retain only elements for which `keep` returns true.
    pub fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let mut out = 0;
        for i in 0..self.len {
            if keep(&self.items[i]) {
                self.items[out] = self.items[i];
                out += 1;
            }
        }
        self.len = out;
    }

    /// The stored elements as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.items[..self.len]
    }

    /// The stored elements as a mutable slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.items[..self.len]
    }

    /// Iterate over stored elements.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }
}

impl<T: Copy, const N: usize> core::ops::Index<usize> for BoundedVec<T, N> {
    type Output = T;
    fn index(&self, idx: usize) -> &T {
        &self.as_slice()[idx]
    }
}

/// A fixed-capacity FIFO queue of `Copy` elements (ring buffer).
#[derive(Debug, Clone, Copy)]
pub struct BoundedQueue<T: Copy, const N: usize> {
    items: [T; N],
    head: usize,
    len: usize,
}

impl<T: Copy + Default, const N: usize> Default for BoundedQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> BoundedQueue<T, N> {
    /// An empty queue.
    pub fn new() -> Self {
        BoundedQueue {
            items: [T::default(); N],
            head: 0,
            len: 0,
        }
    }
}

impl<T: Copy, const N: usize> BoundedQueue<T, N> {
    /// Number of queued elements.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no elements are queued.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True if at capacity.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// Enqueue at the back. Returns `Err(value)` when full.
    pub fn push_back(&mut self, value: T) -> Result<(), T> {
        if self.len == N {
            return Err(value);
        }
        self.items[(self.head + self.len) % N] = value;
        self.len += 1;
        Ok(())
    }

    /// Dequeue from the front.
    pub fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let value = self.items[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(value)
    }

    /// Remove all elements.
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_vec_basics() {
        let mut v: BoundedVec<u32, 3> = BoundedVec::new();
        assert!(v.is_empty());
        v.push(1).unwrap();
        v.push(3).unwrap();
        v.insert(1, 2).unwrap();
        assert_eq!(v.as_slice(), &[1, 2, 3]);
        assert!(v.is_full());
        assert_eq!(v.push(4), Err(4));
        assert_eq!(v.remove(0), Some(1));
        assert_eq!(v.as_slice(), &[2, 3]);
        v.retain(|&x| x != 3);
        assert_eq!(v.as_slice(), &[2]);
        v.clear();
        assert!(v.is_empty());
    }

    #[test]
    fn bounded_queue_wraps() {
        let mut q: BoundedQueue<u8, 2> = BoundedQueue::new();
        q.push_back(1).unwrap();
        q.push_back(2).unwrap();
        assert_eq!(q.push_back(3), Err(3));
        assert_eq!(q.pop_front(), Some(1));
        q.push_back(3).unwrap();
        assert_eq!(q.pop_front(), Some(2));
        assert_eq!(q.pop_front(), Some(3));
        assert_eq!(q.pop_front(), None);
    }
}
