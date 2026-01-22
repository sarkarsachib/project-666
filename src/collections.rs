//! Basic collections for Project 666

use std::collections::VecDeque;

/// Simple queue implementation
#[derive(Debug)]
pub struct Queue<T> {
    items: VecDeque<T>,
    max_size: Option<usize>,
}

impl<T> Queue<T> {
    /// Create a new unbounded queue
    pub fn new() -> Self {
        Queue {
            items: VecDeque::new(),
            max_size: None,
        }
    }

    /// Create a new bounded queue
    pub fn with_capacity(max_size: usize) -> Self {
        Queue {
            items: VecDeque::with_capacity(max_size),
            max_size: Some(max_size),
        }
    }

    /// Push an item to the back of the queue
    pub fn push(&mut self, item: T) -> Result<(), &'static str> {
        if let Some(max) = self.max_size {
            if self.items.len() >= max {
                return Err("Queue is full");
            }
        }
        self.items.push_back(item);
        Ok(())
    }

    /// Pop an item from the front of the queue
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    /// Peek at the front item without removing it
    pub fn peek(&self) -> Option<&T> {
        self.items.front()
    }

    /// Get the number of items in the queue
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Clear all items from the queue
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

impl<T> Default for Queue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_basic() {
        let mut queue = Queue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue.push(1).unwrap();
        queue.push(2).unwrap();
        queue.push(3).unwrap();

        assert_eq!(queue.len(), 3);
        assert_eq!(queue.peek(), Some(&1));
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_queue_bounded() {
        let mut queue = Queue::with_capacity(2);
        queue.push(1).unwrap();
        queue.push(2).unwrap();
        assert!(queue.push(3).is_err());
    }
}
