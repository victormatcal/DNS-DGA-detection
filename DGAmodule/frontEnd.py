#!/usr/bin/ python
"""
Frontend to receive DNS queries and schedule the task to answer them.
"""

import logging
import socket
from threading import Thread, Lock, Event
import datetime
from dataclasses import dataclass, astuple

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

from utils import IPAddress, SharedMemory
from config import frontEndConfig as config
import classifiers as cls
import cache


# Logging
logging.basicConfig(filename = 'logs/DGAmodule.log',
                    format = '%(asctime)s : %(levelname)s : %(name)s : %(message)s',
                    level = logging.DEBUG)
logger = logging.getLogger("FRONTEND")


class FrontEnd:
    """Scheduler class. It waits for a UDP datagram and handles the response"""
    def __init__(self):
        self._serverAddress: IPAddress = config.DNSServer.address
        self._DNSResolverAddress: IPAddress = config.DNSResolver
        self._SinkholeAddress: IPAddress = config.Sinkhole
        self.bufferSize: int = config.DNSServer.bufferSize
        logger.info("Parameters set successfully")

    @property
    def UDPServerSocket(self) -> socket:
        return self._UDPServerSocket

    @UDPServerSocket.setter
    def UDPServerSocket(self, UDPServerSocket: socket) -> None:
        self._UDPServerSocket: socket = UDPServerSocket
        self._UDPServerSocket.bind(astuple(self._serverAddress))
        logger.info("UDP Socket binded successfully on %s:%i" % astuple(self._serverAddress))
        # Console
        print("\n[*] UDP server up and listening on:")
        print("    IP: %s" % self._serverAddress.ip)
        print("    Port: %i\n" % self._serverAddress.port)

    def _sinkholeResponse(self, query: dns.message.Message, ttl: int = 30) -> dns.message.Message:
        """Generates a message with the sinkhole address.

        Arguments:
            query -- Original query sent by the user.

        Keyword Arguments:
            ttl -- ttl for the sinkhole response (default: {30})

        Returns:
            Sinkhole message ready for sending to the user.
        """
        sinkholeMessage = dns.message.make_response(query)

        rdclass = dns.rdataclass.IN
        rdtype = dns.rdatatype.A
        Rdata = dns.rdata.from_text(rdclass, rdtype, self._SinkholeAddress.ip)

        name = query.question[0].name
        answer = dns.rrset.from_rdata(name, ttl, Rdata)

        sinkholeMessage.answer = [answer]

        return sinkholeMessage

    def _sendResponse(self, isMalicious: bool, dnsQuery: dns.message.Message, address: IPAddress):
        """Sends a DNS response to the address.

        Arguments:
            isMalicious -- True if the domain is malicious.
            dnsQuery -- The DNS query that was sent by the user.
            address -- IPAddress object that contains the IP and the port of the receiver.
        """
        if isMalicious:
            response = self._sinkholeResponse(dnsQuery)
            tStoreForReport = Thread(target = c.storeForReport, args=(str(dnsQuery.question[0].name)[:-1],
                                     datetime.datetime.utcnow().isoformat(), astuple(address)))
            tStoreForReport.start()
        else:
            response = dns.query.udp(dnsQuery, self._DNSResolverAddress.ip)

        # Send response
        self._UDPServerSocket.sendto(response.to_wire(), astuple(address))
        logger.info("Response sent to address: %s:%i" % astuple(address))

    def _handleClassifierResponse(self, tCl: Thread, response: dict, dnsQuery: dns.message.Message, address: IPAddress, domain: str):
        tCl.start()

        # Wait for the classifier to finish
        tCl.join()

        if response["firstResponse"]:
            self._sendResponse(response["isMalicious"], dnsQuery, address)
            print("\n[*] %s - %s : %s\n" % (response["classOfCl"].upper(), domain, response["isMalicious"]))

            logger.info("%s got first on answering query for %s" % (response["classOfCl"].upper(), domain))

        # Store result on cache
        tStore = Thread(target = c.store, args=(domain, response["isMalicious"], astuple(address), response["classOfCl"]))
        tStore.start()

        logger.info("%s - is %s malicious?: %s" % (response["classOfCl"].upper(), domain, response["isMalicious"]))

    def handleQuery(self, datagramBytes: bytes, address: IPAddress):
        """Handles the query received.

        Arguments:
            datagramBytes -- bytes of the UDP datagram received.
            address -- IPAddress that contains the IP and the port of the receiver.
        """
        # Transform bytes to dns.message.Message
        dnsQuery: dns.message.Message = dns.message.from_wire(datagramBytes)

        # Obtain the domain removing the last dot
        domain: str = str(dnsQuery.question[0].name)[:-1]

        # Cache search
        cacheResponse = c.search(domain)

        # In cache
        if (cacheResponse is not None):
            self._sendResponse(cacheResponse, dnsQuery, address)
            print("\n[*] CACHE - %s : %s\n" % (domain, cacheResponse))

        # Not in cache
        else:
            # Shared memory for the classifiers
            sM = SharedMemory()

            # Classifiers
            for cl in classifiersList:
                response = {}
                tCL = Thread(target = cl.classify, args=(domain, sM, response))
                handleCl = Thread(target = self._handleClassifierResponse, args=(tCL, response, dnsQuery, address, domain))
                handleCl.start()


if __name__ == '__main__':
    # Frontend
    f = FrontEnd()
    logger.debug("FrontEnd was created successfully.")

    # Create Cache
    c = cache.Cache()
    logger.debug("Cache was created successfully.")

    # Create RandomForest classifier
    RF = cls.Classifier(cls.algorithms.RandomForest())
    logger.debug("RandomForest was created successfully.")

    # Create LSTM classifier
    LSTM = cls.Classifier(cls.algorithms.LSTM())
    logger.debug("LSTM was created successfully.")

    #List of classifiers
    classifiersList = [RF, LSTM]

    # Create UDP Socket
    f.UDPServerSocket = socket.socket(family=socket.AF_INET,
                                      type=socket.SOCK_DGRAM)
    logger.debug("UDPServerSocket was created successfully.")

    # Listen for incoming datagrams
    while(True):
        try:
            # Wait for a UDP Datagram
            datagramBytes, tuple_address = f.UDPServerSocket.recvfrom(f.bufferSize)

            # Redirect to a Response Thread
            t = Thread(target = f.handleQuery, args=(datagramBytes, IPAddress(*tuple_address)))
            t.start()

            logger.debug("Query received and sent to handle.")

        except KeyboardInterrupt:
            print("\r", end="")
            print("DGA DNS module was interrupted.")
            logger.debug("Program was interrupted.")
            break
