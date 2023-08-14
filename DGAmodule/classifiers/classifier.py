from utils import SharedMemory
from .algorithms.algorithm import Algorithm


class Classifier:
    def __init__(self, algorithm: Algorithm):
        self._algorithm: Algorithm = algorithm

    # Algorithm property with setter and getter
    @property
    def algorithm(self) -> "Algorithm":
        return self._algorithm

    @algorithm.setter
    def algorithm(self, algorithm: "Algorithm") -> None:
        self._algorithm: Algorithm = algorithm

    def classify(self, domain: str, sM: SharedMemory, response: dict):
        """Method to classify a domains as malicious or not

        Arguments:
            domain -- domain to classify
            sM -- sharedMemory object shared between classifiers
            response -- dictionary where to return the response
        """
        # Predict domain
        isMalicious = self._algorithm.predict(domain)

        with sM.lock:
            firstResponse = not sM.firstReply
            # If it is the first classifier to respond
            if firstResponse:
                sM.firstReply = True

        response["firstResponse"] = firstResponse
        response["isMalicious"] = isMalicious
        response["classOfCl"] = str(self._algorithm)

    def __str__(self) -> str:
        """Returns the algorithm used by the classifier

        Returns:
            String telling the algorithm in use.
        """
        return str(self.algorithm)
