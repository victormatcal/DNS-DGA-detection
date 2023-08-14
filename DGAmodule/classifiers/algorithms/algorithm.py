import abc

class Algorithm(abc.ABC):
    @abc.abstractmethod
    def predict(self, domain: str) -> bool:
        raise NotImplementedError