#!/usr/bin/env python3
"""
Frankenstein Zimbra Email Signature Checker (Full MIME Retrieval with Login Dialog)

Workflow:
  1. When you run the script, a modal login dialog appears.
  2. Enter your Zimbra username and password and click "Login". (Use the same credentials that previously worked.)
  3. Upon successful login, the main window launches (without any login fields) and you set the search parameters.
  4. Click "Search" to perform the query.

This version leverages Zimbra’s built-in content search to narrow down the results to those
that contain the agent’s name. The filtering logic to decide whether an email truly came from the agent
has been refined: we remove quoted text but if that filtering removes almost all content, we fall back
to searching the full email.
"""

import sys
import requests
import xml.etree.ElementTree as ET
import logging
import re
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QFormLayout, QLineEdit,
    QLabel, QPushButton, QDateEdit, QMessageBox, QCheckBox, QDialog, QDialogButtonBox, QGroupBox, QGridLayout
)
from PyQt5.QtCore import QDate, Qt
from PyQt5.QtGui import QPalette, QColor, QCursor
from bs4 import BeautifulSoup
from email import policy
from email.parser import BytesParser

# =====================================================
# Global Folder Groups Definition
# =====================================================
FOLDER_GROUPS = {
    "Central State Sites": [
        "websupport@corporatetools.com/Central/Sent/WebSupport - legalregisteredagentservices.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/WebSupport - texasregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - alabamaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - arkansasregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - illinoisregisteredagent.net’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - indianaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - iowaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - kansasregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - kentuckyregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - louisianaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - michiganregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - minnesotaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - mississippiregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - missouriregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - nebraskaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - northdakotaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - northdakotaregisteredagent.net’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - ohioregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - ohiostatutoryagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - oklahomaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - southdakotaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - tennesseeregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - texasregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - texasregisteredagent.net’s Sent",
        "websupport@corporatetools.com/Central/Sent/Websupport - wisconsinregisteredagent.net’s Sent"
    ],
    "NE State Sites": [
        "websupport@corporatetools.com/NE/Sent/WebSupport - bestdelawareregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - abestregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - cheapestdelawareregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - connecticutregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - dashincorporators.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - delawareregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - delawareregisteredagentservice.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - maineregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - marylandregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - marylandresidentagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - massachusettsregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - newhampshireregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - newjerseyregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - newyorkllcs.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - newyorkregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - pacommercialregisteredofficeprovider.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - pennsylvaniaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - radregisteredagents.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - rhodeislandregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - vermontregisteredagent.com’s Sent",
        "websupport@corporatetools.com/NE/Sent/WebSupport - washingtondcregisteredagent.com’s Sent"
    ],
    "SE State Sites": [
        "websupport@corporatetools.com/SE/Sent/WebSupport - registeredagentflorida.com’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - varegisteredagent.com’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - floridaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - floridaregisteredagent.net’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - georgiaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - northcarolinaregisteredagent.net’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - southcarolinaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - virginia-registeredagent.net’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - virginiaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/SE/Sent/WebSupport - westvirginiaregisteredagent.com’s Sent"
    ],
    "Western State Sites": [
        "websupport@corporatetools.com/Western/Sent/Websupport - processagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - 49dollaridahoregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - alaskaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - arizonaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - arizonastatutoryagent.net’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - cacorporateagents.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - california-registered-agent.net’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - californiaagentforserviceofprocess.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - californiaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - californiaregisteredagent.net’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - californiaregisteredagents.net’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - coloradollcs.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - coloradoregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - hawaiiregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - idahoregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - nevadaresidentagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - newmexicoregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - oregonllcs.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - oregonregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - utahregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - washingtonllcs.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - washingtonregisteredagent.com’s Sent",
        "websupport@corporatetools.com/Western/Sent/Websupport - washingtonregisteredagent.net’s Sent"
    ],
    "WY - MT State Sites": [
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - commercialregisteredagent.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - corporationregisteredagent.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - incorporate.me’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - llc-registeredagent.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - statutoryagent.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - wyomingmailforwarding.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - 49dollarmontanaregisteredagent.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - activefilings.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - aregisteredagent.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - awesomewyomingregisteredagent.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - bestwyomingregisteredagent.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - filingsmadeeasy.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - form-a-corp.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - formed.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - incorporatefast.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - montanaregisteredagent.net’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - nationalregisteredagentservice.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - registeredagentsinc.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - residentagent.net’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - speedy-incorporation.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - wyomingagents.com’s Sent",
        "websupport@corporatetools.com/WY - MT - Nationals/Sent/WebSupport - wyregisteredagent.net’s Sent"
    ],
    "Northwest": [
        "websupport@northwestregisteredagent.com/sent"
    ]
}

# =====================================================
# Logging Configuration
# =====================================================
VERIFY_SSL = True   # Set to False if using self-signed certificates
DEBUG = True        # Enable debug logging

logger = logging.getLogger("ZimbraEmailSignatureChecker")
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)
fh = logging.FileHandler("debug.log")
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =====================================================
# Utility Function: Convert MIME to Plain Text
# =====================================================
def mime_to_plain_text(mime_content):
    """
    Parse the full MIME content (bytes) and return the plain text part.
    If no text/plain is found, falls back to stripping HTML.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(mime_content)
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_content()
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html = part.get_content()
                soup = BeautifulSoup(html, "html.parser")
                return soup.get_text(separator="\n")
    except Exception as e:
        logger.error("MIME parsing error: %s", e)
    return ""

# =====================================================
# Utility Function to Filter Quoted Content
# =====================================================
def remove_quoted_text(text):
    """
    Remove lines that are likely part of quoted replies (starting with '>').
    """
    lines = text.splitlines()
    non_quoted = [line for line in lines if not line.strip().startswith('>')]
    return "\n".join(non_quoted)

# =====================================================
# Refined Function for Content Analysis
# =====================================================
def is_email_from_rep(content, rep_alias):
    """
    Checks if the representative alias (case-insensitive whole word)
    appears in the non-quoted portions of an email.
    If removing quoted text leaves almost no content, fall back to checking the full text.
    """
    full_text = mime_to_plain_text(content) if isinstance(content, bytes) else content
    filtered_text = remove_quoted_text(full_text)
    # Calculate the ratio of non-quoted content length to the full text length
    ratio = len(filtered_text) / (len(full_text) + 1)  # guard against division by zero

    rep_alias_lower = rep_alias.lower()
    pattern = r'\b' + re.escape(rep_alias_lower) + r'\b'
    
    # Check filtered text first.
    if re.search(pattern, filtered_text.lower()):
        logger.debug("Representative alias '%s' found in non-quoted email content.", rep_alias)
        return True
    # If too little content remains after filtering, check full content
    elif ratio < 0.3 and re.search(pattern, full_text.lower()):
        logger.debug("Representative alias '%s' found in full email content (fallback, ratio=%.2f).", rep_alias, ratio)
        return True
    else:
        logger.debug("Representative alias '%s' not found (non-quoted ratio: %.2f).", rep_alias, ratio)
        return False

def format_date_for_query(date_obj):
    """
    Format a Python date into "MM/DD/YYYY" format as required by the query.
    """
    return date_obj.strftime("%m/%d/%Y")

# =====================================================
# ZimbraClient: Handles SOAP API calls to Zimbra.
# =====================================================
class ZimbraClient:
    def __init__(self, server_url, username, password, verify_ssl=VERIFY_SSL):
        self.server_url = server_url
        self.username = username
        self.password = password
        self.auth_token = None
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.login()

    def login(self):
        envelope = f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <AuthRequest xmlns="urn:zimbraAccount">
      <account by="name">{self.username}</account>
      <password>{self.password}</password>
    </AuthRequest>
  </soap:Body>
</soap:Envelope>'''
        headers = {'Content-Type': 'application/soap+xml'}
        response = self.session.post(self.server_url, data=envelope.encode('utf-8'), headers=headers, verify=self.verify_ssl)
        logger.debug("Raw login response:")
        logger.debug(response.text)
        if response.status_code == 200:
            try:
                root = ET.fromstring(response.content)
                auth_token_elem = root.find('.//{urn:zimbraAccount}authToken')
                if auth_token_elem is not None:
                    self.auth_token = auth_token_elem.text
                    logger.debug("Auth token received.")
                else:
                    raise Exception("Authentication failed: no auth token found.")
            except ET.ParseError as e:
                raise Exception(f"Failed to parse login response: {e}")
        else:
            raise Exception(f"Login failed with status code {response.status_code}.")

    def search_emails(self, folders, start_date, end_date, rep_alias=None):
        start_str = format_date_for_query(start_date)
        end_str = format_date_for_query(end_date)
        if not folders:
            raise Exception("No folders specified for search.")

        # Narrow search results using Zimbra's built-in content search if rep_alias is provided.
        if rep_alias:
            content_filter = f'content:"{rep_alias}"'
        else:
            content_filter = ""

        if len(folders) == 1:
            folder_query = f'in:"{folders[0]}"'
        else:
            folder_query = "(" + " OR ".join([f'in:"{f}"' for f in folders]) + ")"
        query = f'{folder_query} {content_filter} is:anywhere after:"{start_str}" before:"{end_str}"'
        logger.debug("Search query: %s", query)
        envelope = f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <context xmlns="urn:zimbra">
      <authToken>{self.auth_token}</authToken>
    </context>
  </soap:Header>
  <soap:Body>
    <SearchRequest types="message" xmlns="urn:zimbraMail" limit="1000">
      <query>{query}</query>
    </SearchRequest>
  </soap:Body>
</soap:Envelope>'''
        headers = {'Content-Type': 'application/soap+xml'}
        response = self.session.post(self.server_url, data=envelope.encode('utf-8'), headers=headers, verify=self.verify_ssl)
        logger.debug("Raw search response:")
        logger.debug(response.text)
        if response.status_code == 200:
            try:
                root = ET.fromstring(response.content)
                fault = root.find('.//{http://www.w3.org/2003/05/soap-envelope}Fault')
                if fault is not None:
                    fault_text = fault.findtext('.//{http://www.w3.org/2003/05/soap-envelope}Text')
                    raise Exception(f"SOAP Fault in search emails: {fault_text or 'Unknown fault'}")
                messages = []
                for msg in root.findall('.//{urn:zimbraMail}m'):
                    message = {
                        'id': msg.get('id'),
                        'conversationId': msg.get('cid'),
                        'date': int(msg.get('d')) if msg.get('d') is not None else 0
                    }
                    messages.append(message)
                logger.debug("Number of messages found: %s", len(messages))
                return messages
            except ET.ParseError as e:
                raise Exception(f"Failed to parse search response: {e}")
        else:
            raise Exception(f"Search emails failed. HTTP status code {response.status_code}.")

    def get_message_details(self, message_id):
        envelope = f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <context xmlns="urn:zimbra">
      <authToken>{self.auth_token}</authToken>
    </context>
  </soap:Header>
  <soap:Body>
    <GetMsgRequest xmlns="urn:zimbraMail">
      <m id="{message_id}" fetch="all" truncate="0" />
    </GetMsgRequest>
  </soap:Body>
</soap:Envelope>'''
        headers = {'Content-Type': 'application/soap+xml'}
        response = self.session.post(self.server_url, data=envelope.encode('utf-8'), headers=headers, verify=self.verify_ssl)
        logger.debug("Raw GetMsg response for message id %s:", message_id)
        logger.debug(response.text)
        if response.status_code == 200:
            try:
                return response.content, None
            except Exception as e:
                raise Exception(f"Failed to retrieve full message content: {e}")
        else:
            raise Exception(f"Get message details failed. HTTP status code {response.status_code}.")

    def get_conversation_messages(self, conv_id):
        envelope = f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <context xmlns="urn:zimbra">
      <authToken>{self.auth_token}</authToken>
    </context>
  </soap:Header>
  <soap:Body>
    <GetConvRequest xmlns="urn:zimbraMail" fetch="all" truncate="0">
      <c id="{conv_id}" />
    </GetConvRequest>
  </soap:Body>
</soap:Envelope>'''
        headers = {'Content-Type': 'application/soap+xml'}
        response = self.session.post(self.server_url, data=envelope.encode('utf-8'), headers=headers, verify=self.verify_ssl)
        logger.debug("Raw GetConv response for conversation id %s:", conv_id)
        logger.debug(response.text)
        if response.status_code == 200:
            try:
                root = ET.fromstring(response.content)
                messages = []
                for msg in root.findall('.//{urn:zimbraMail}m'):
                    m = {
                        'id': msg.get('id'),
                        'date': int(msg.get('d')) if msg.get('d') is not None else 0,
                        'content': b""
                    }
                    for mp in msg.findall('.//{urn:zimbraMail}mp'):
                        for c in mp.findall('.//{urn:zimbraMail}content'):
                            m['content'] += (c.text or "").encode('utf-8')
                    if not m['content']:
                        for c in msg.findall('.//{urn:zimbraMail}content'):
                            m['content'] = (c.text or "").encode('utf-8')
                            break
                    messages.append(m)
                logger.debug("Number of messages in conversation %s: %s", conv_id, len(messages))
                return messages
            except ET.ParseError as e:
                raise Exception(f"Failed to parse GetConv response: {e}")
        else:
            raise Exception(f"Get conversation messages failed. HTTP status code {response.status_code}.")

# =====================================================
# EmailSearcher: Business logic for filtering emails.
# =====================================================
class EmailSearcher:
    def __init__(self, zimbra_client):
        self.client = zimbra_client

    def count_representative_emails(self, folders, start_date, end_date, rep_alias):
        # Let Zimbra narrow down the results with rep_alias via its content search.
        messages = self.client.search_emails(folders, start_date, end_date, rep_alias=rep_alias)
        total_emails = len(messages)
        logger.debug("Total messages retrieved from search: %s", total_emails)

        conv_groups = {}
        non_conv_messages = []
        for msg in messages:
            conv_id = msg.get('conversationId')
            if conv_id:
                conv_groups.setdefault(conv_id, []).append(msg)
            else:
                non_conv_messages.append(msg)

        count = 0

        # Process non-conversation messages.
        for msg in non_conv_messages:
            mime_content, _ = self.client.get_message_details(msg['id'])
            full_text = mime_to_plain_text(mime_content)
            logger.debug("Non-conversation message %s full text: %s", msg['id'], full_text)
            if is_email_from_rep(full_text, rep_alias):
                logger.debug("Counting non-conversation message %s", msg['id'])
                count += 1
            else:
                logger.debug("Not counting non-conversation message %s", msg['id'])

        # Process conversation messages.
        for conv_id, msgs in conv_groups.items():
            conv_messages = self.client.get_conversation_messages(conv_id)
            if conv_messages:
                latest_msg = max(conv_messages, key=lambda m: m['date'])
                mime_content, _ = self.client.get_message_details(latest_msg.get('id'))
                full_text = mime_to_plain_text(mime_content)
                logger.debug("Conversation %s full text from latest message (re-fetched): %s", conv_id, full_text)
                if is_email_from_rep(full_text, rep_alias):
                    logger.debug("Counting conversation %s", conv_id)
                    count += 1
                else:
                    logger.debug("Not counting conversation %s", conv_id)
            else:
                logger.debug("No messages returned for conversation %s", conv_id)

        return count, total_emails

# =====================================================
# LoginDialog: Modal QDialog for login.
# =====================================================
class LoginDialog(QDialog):
    def __init__(self, server_url, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Zimbra Login")
        self.server_url = server_url
        self.client = None

        layout = QFormLayout(self)
        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Enter username")
        layout.addRow("Username:", self.username_input)
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Password:", self.password_input)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        layout.addWidget(self.button_box)
        self.button_box.accepted.connect(self.handle_login)
        self.button_box.rejected.connect(self.reject)

    def handle_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please enter both username and password.")
            return
        try:
            self.client = ZimbraClient(self.server_url, username, password, verify_ssl=VERIFY_SSL)
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Login Failed", f"An error occurred during login:\n{e}")
            logger.error("Login error: %s", e)

# =====================================================
# MainWindow: Main search window.
# =====================================================
class MainWindow(QWidget):
    def __init__(self, zimbra_client):
        super().__init__()
        self.setWindowTitle("Zimbra Email Checker v2.1")
        self.zimbra_client = zimbra_client
        self.email_searcher = EmailSearcher(self.zimbra_client)
        self.folder_checkboxes = {}
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        form_layout = QFormLayout()

        # Dynamically create a group box for folder groups checkboxes.
        folder_group_box = QGroupBox("Folder Groups")
        folder_layout = QGridLayout()

        row = 0
        col = 0
        for group in FOLDER_GROUPS:
            checkbox = QCheckBox(group)
            self.folder_checkboxes[group] = checkbox
            folder_layout.addWidget(checkbox, row, col)
            col += 1
            if col >= 2:
                col = 0
                row += 1
        folder_group_box.setLayout(folder_layout)
        form_layout.addRow(folder_group_box)

        # Date range.
        self.start_date_edit = QDateEdit()
        self.start_date_edit.setCalendarPopup(True)
        self.start_date_edit.setDisplayFormat("MM/dd/yyyy")
        self.start_date_edit.setDate(QDate(2025, 1, 1))
        form_layout.addRow("Start Date:", self.start_date_edit)

        self.end_date_edit = QDateEdit()
        self.end_date_edit.setCalendarPopup(True)
        self.end_date_edit.setDisplayFormat("MM/dd/yyyy")
        self.end_date_edit.setDate(QDate.currentDate())
        form_layout.addRow("End Date:", self.end_date_edit)

        # Representative alias.
        self.rep_alias_input = QLineEdit()
        self.rep_alias_input.setPlaceholderText("Representative Alias")
        form_layout.addRow("Representative Alias:", self.rep_alias_input)

        layout.addLayout(form_layout)

        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.perform_search)
        layout.addWidget(self.search_button)

        self.result_label = QLabel("Result: ")
        layout.addWidget(self.result_label)

        self.setLayout(layout)
        self.resize(800, 600)

    def perform_search(self):
        selected_folders = []
        # Gather folders from all checked group checkboxes.
        for group, checkbox in self.folder_checkboxes.items():
            if checkbox.isChecked():
                selected_folders.extend(FOLDER_GROUPS[group])
        if not selected_folders:
            QMessageBox.warning(self, "Input Error", "Please select at least one folder group.")
            return

        rep_alias = self.rep_alias_input.text().strip()
        if not rep_alias:
            QMessageBox.warning(self, "Input Error", "Please enter a representative alias.")
            return

        start_date = self.start_date_edit.date().toPyDate()
        end_date = self.end_date_edit.date().toPyDate()

        self.result_label.setText("Searching...")
        QApplication.processEvents()

        try:
            match_count, total_emails = self.email_searcher.count_representative_emails(
                selected_folders, start_date, end_date, rep_alias
            )
            self.result_label.setText(f"Result: {rep_alias} sent {match_count} new email(s) out of {total_emails} emails searched.")
            logger.info("Search complete: %s emails found for alias '%s' out of %s emails searched.", match_count, rep_alias, total_emails)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            self.result_label.setText("Result: Error occurred.")
            logger.error("An error occurred during search: %s", e)

# =====================================================
# Main: Launch login dialog then main window; set dark mode & position window.
# =====================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set Fusion style and dark palette.
    app.setStyle("Fusion")
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.WindowText, Qt.white)
    dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
    dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
    dark_palette.setColor(QPalette.ToolTipText, Qt.white)
    dark_palette.setColor(QPalette.Text, Qt.white)
    dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ButtonText, Qt.white)
    dark_palette.setColor(QPalette.BrightText, Qt.red)
    dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(dark_palette)
    
    server_url = "https://m1.corporatetools.com/service/soap"
    
    # Launch the login dialog and obtain the zimbra_client.
    login_dialog = LoginDialog(server_url)
    if login_dialog.exec() == QDialog.Accepted:
        zimbra_client = login_dialog.client
        main_window = MainWindow(zimbra_client)
        
        # Position main window based on current cursor position.
        from PyQt5.QtGui import QCursor
        cursor_pos = QCursor.pos()
        screen = app.screenAt(cursor_pos)
        if screen:
            geom = screen.geometry()
            main_window.move(geom.center() - main_window.rect().center())
        
        main_window.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)
