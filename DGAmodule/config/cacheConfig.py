import configparser

from utils import IPAddress

config = configparser.ConfigParser()
config.optionxform = lambda option: option
config.read('config/config.ini')

# Configuration parameters
cache = IPAddress(ip = config["CacheServer"]["CacheIP"],
                port = int(config["CacheServer"]["CachePort"]))
dbName = config["Database"]["dbName"]
domainsColName = config["Database"]["domainsColName"]
reportColName = config["Database"]["reportColName"]
cleanFile = config["PrestoreData"]["cleanFile"]
maliciousFile = config["PrestoreData"]["maliciousFile"]
emailFrom = config["Notifications"]["emailFrom"]
emailAdmin = config["Notifications"]["emailAdmin"]
emailSubject = config["Notifications"]["emailSubject"]
emailTemplate = config["Notifications"]["emailTemplate"]
smtpUser = config["Notifications"]["smtpUser"]
smtpPassword = config["Notifications"]["smtpPassword"]




