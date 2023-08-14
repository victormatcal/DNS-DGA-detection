from threading import Lock

class SharedMemory:
    """Shared memory for threads and frontEnd."""
    def __init__(self):
        self._firstReply: bool = False
        self.lock: Lock = Lock()

    # firstReply property with setter and getter
    @property
    def firstReply(self) -> bool:
        return self._firstReply

    @firstReply.setter
    def firstReply(self, firstReply: bool) -> None:
        self._firstReply: bool = firstReply
