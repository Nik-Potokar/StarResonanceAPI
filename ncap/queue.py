"""
Thread-safe generic queue
"""
import threading
from typing import Generic, TypeVar, Optional, Tuple
from collections import deque

T = TypeVar('T')


class Queue(Generic[T]):
    """Thread-safe FIFO queue"""

    def __init__(self):
        """Initialize queue"""
        self.items: deque[T] = deque()
        self.lock = threading.Lock()

    def enqueue(self, item: T):
        """
        Add item to queue

        Args:
            item: Item to add
        """
        with self.lock:
            self.items.append(item)

    def dequeue(self) -> Tuple[Optional[T], bool]:
        """
        Remove and return item from queue

        Returns:
            Tuple of (item, success)
        """
        with self.lock:
            if len(self.items) == 0:
                return None, False
            return self.items.popleft(), True

    def front(self) -> Tuple[Optional[T], bool]:
        """
        Peek at front item without removing

        Returns:
            Tuple of (item, success)
        """
        with self.lock:
            if len(self.items) == 0:
                return None, False
            return self.items[0], True

    def is_empty(self) -> bool:
        """Check if queue is empty"""
        with self.lock:
            return len(self.items) == 0

    def size(self) -> int:
        """Get queue size"""
        with self.lock:
            return len(self.items)

    def clear(self):
        """Clear all items from queue"""
        with self.lock:
            self.items.clear()
