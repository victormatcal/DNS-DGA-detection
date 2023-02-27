#!/usr/bin/ python
"""
Cache used to store domain classification.
"""

import logging
import pathlib
import datetime
from threading import Thread, Lock
import requests
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pymongo
import lxml.html
from jinja2 import Environment, PackageLoader, select_autoescape

from config import cacheConfig as config

# scheduler absolute path
path = str(pathlib.Path(__file__).parent.absolute())

# Logging
logger = logging.getLogger("CACHE")

class Cache:
  def __init__(self):
    # Connect to database
    myclient = pymongo.MongoClient("mongodb://" + config.cache.ip + ":" + str(config.cache.port) + "/")
    mydb = myclient[config.dbName]

    # Create database and collection
    self._domainsCol = mydb[config.domainsColName]
    self._reportCol = mydb[config.reportColName]
    logger.info("Connection to database done successfully!")

    self._domainsLock: Lock = Lock()
    self._reportLock: Lock = Lock()

    self._cleanFilePath: pathlib.PosixPath = pathlib.Path(path + "/data/" + config.cleanFile)
    self._maliciousFilePath: pathlib.PosixPath = pathlib.Path(path + "/data/" + config.maliciousFile)
    # Prestore clean domains
    with open(self._cleanFilePath) as f:
      for line in f:
        domainName = line.rstrip('\n')
        self.store(domainName, False)

    # Prestore malicious domains
    with open(self._maliciousFilePath) as f:
      for line in f:
        domainName = line.rstrip('\n')
        self.store(domainName, True)

  def search(self, domain: str) -> bool:
    """Searchs the malicious classification for a given domain.

    Arguments:
        domain -- Domain to search.

    Returns:
        It returns true if it is malicious, otherwise false.
    """
    result = self._domainsCol.find_one({"_id": domain}, {"_id": 0, "isMalicious":1})

    return result if result is None else result["isMalicious"]

  def store(self, domain: str, isMalicious: bool, address: tuple = None, classOfCl: str = "default"):
    """Adds or updates a database domain.

    Arguments:
        domain -- Domain to add or update.
        isMalicious -- Classification for the domain. True if it is malicious.

    Keyword Arguments:
        address -- Tuple that contains the IP and the port of the user. (default: {None})
    """

    timestamp = datetime.datetime.utcnow().isoformat()

    # Store or update
    if classOfCl == "LSTM":
      try:
        # Mutual exclusion
        with self._domainsLock:
          self._domainsCol.insert_one({
            "_id": domain,
            "timestamp": timestamp,
            "isMalicious": isMalicious,
            "classifier": classOfCl
          })
          logger.debug("LSTM store first")
      except pymongo.errors.DuplicateKeyError:
        # Mutual exclusion
        with self._domainsLock:
          self._domainsCol.update_one({"_id": domain}, {"$set": {"timestamp": timestamp, "isMalicious": isMalicious, "classifier": classOfCl}})
          logger.debug("LSTM updated registry")
    # Store
    else:
      try:
        # Mutual exclusion
        with self._domainsLock:
          self._domainsCol.insert_one({
            "_id": domain,
            "timestamp": timestamp,
            "isMalicious": isMalicious,
            "classifier": classOfCl
          })
          logger.debug("RF store first")
      except pymongo.errors.DuplicateKeyError:
        logger.debug("RF tried to update registry")

  def storeForReport (self, domain: str, timestamp: datetime.datetime, address: tuple):
    """Adds a malicious domain to the report collection.

    Arguments:
        domain -- Domain to add or update.
        timestamp -- The time when the domain was asked.
        address -- Tuple that contains the IP and the port of the user. (default: {None})
    """
    # Mutual exclusion
    with self._reportLock:
      self._reportCol.insert_one({
        "domain": domain,
        "timestamp": timestamp,
        "address": address
      })

  def _deleteOldDomains (self, timestamp: datetime.datetime):
    """Deletes all the entries with a timestamp older than the given.

    Arguments:
        timestamp -- Reference timestamp.
    """
    self._domainsCol.delete_many({ "timestamp": {"$lt": timestamp} })

  def _notifyAdmin (self):
    domainsDetailed = [doc for doc in self._reportCol.find()]

    pipeline = [{
        "$group": {
            "_id": "$domain",
            "count": { "$sum": 1 },
        }
    }]
    domainsSummary = [doc for doc in self._reportCol.aggregate(pipeline)]

    msg = MIMEMultipart('related')
    msg['From'] = config.emailFrom
    msg['To'] = config.emailAdmin
    msg['Subject'] = config.emailSubject
    msg.preamble = 'This is a multi-part message in MIME format.'
    msg_alternative = MIMEMultipart('alternative')
    msg.attach(msg_alternative)

    # html template
    env = Environment(
        loader=PackageLoader('cache'),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template(config.emailTemplate)
    message = template.render({
        'domainsSummary': domainsSummary,
        'domainsDetailed': domainsDetailed
    })

    part_text = MIMEText(lxml.html.fromstring(message).text_content().encode('utf-8'), 'plain', _charset='utf-8')
    part_html = MIMEText(message.encode('utf-8'), 'html', _charset='utf-8')
    msg_alternative.attach(part_text)
    msg_alternative.attach(part_html)

    s = smtplib.SMTP('smtp.mailgun.org', 587)

    s.login(config.smtpUser, config.smtpPassword)
    s.sendmail(msg['From'], msg['To'], msg.as_string())
    s.quit()
