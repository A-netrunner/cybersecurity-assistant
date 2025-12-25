# ai_agent/memory_store.py
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class MemoryStore:
    """
    Safe in-memory store for agent events and incidents.
    Never crashes if a bucket is missing.
    """

    def __init__(self):
        # ✅ All buckets initialized
        self.store: Dict[str, List[Any]] = {
            "short_term": [],   # recent interactions
            "incidents": [],    # confirmed malicious events
            "long_term": []     # learned patterns
        }

    def add(self, bucket: str, data: Any) -> None:
        """
        Safely add data to a memory bucket.
        """
        try:
            if bucket not in self.store:
                self.store[bucket] = []

            self.store[bucket].append(data)

        except Exception as e:
            logger.warning("Memory store failed: %s", e)

    def get(self, bucket: str) -> List[Any]:
        """
        Get memory bucket safely.
        """
        return self.store.get(bucket, [])

    def clear(self, bucket: str) -> None:
        """
        Clear a memory bucket.
        """
        if bucket in self.store:
            self.store[bucket].clear()

    def stats(self) -> Dict[str, int]:
        """
        Memory usage statistics.
        """
        return {k: len(v) for k, v in self.store.items()}
