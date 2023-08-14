from dataclasses import dataclass
import configparser

from utils import IPAddress

@dataclass
class DNSServer(IPAddress):
    bufferSize: int

    @property
    def address(self) -> IPAddress:
        return IPAddress(self.ip, self.port)

    @address.setter
    def address(self, newAddress: IPAddress) -> None:
        self.ip: str = newAddress.ip
        self.port: int = newAddress.port

config = configparser.ConfigParser()
config.optionxform = lambda option: option
config.read('config/config.ini')

# Configuration parameters
DNSServer: DNSServer = DNSServer(ip = config["DNSServer"]["DNSServerIP"],
                                 port = int(config["DNSServer"]["DNSServerPort"]),
                                 bufferSize = int(config["DNSServer"]["DNSServerBufferSize"]))

DNSResolver: IPAddress = IPAddress(ip = config["DNSResolver"]["DNSResolverIP"],
                               port = int(config["DNSResolver"]["DNSResolverPort"]))

Sinkhole: IPAddress = IPAddress(ip = config["Sinkhole"]["SinkholeIP"],
                            port = int(config["Sinkhole"]["SinkholePort"]))

classifiersList = [key for key in config["Algorithms"].keys() if config["Algorithms"][key] == "True"]
