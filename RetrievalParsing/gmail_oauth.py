import os
import base64
import sqlite3
import re
from io import StringIO
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from email import message_from_bytes

# Scope: Read-only Gmail access
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_oauth_config():
    return {
        "installed": {
            "client_id": os.environ.get("GMAIL_CLIENT_ID"),
            "client_secret": os.environ.get("GMAIL_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "redirect_uris": ["http://localhost"]
        }
    }

def authorize():
    creds = None
    if os.path.exists('RetrievalParsing/secrets/token.json'):
        creds = Credentials.from_authorized_user_file('RetrievalParsing/secrets/token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            config = get_oauth_config()
            flow = InstalledAppFlow.from_client_config(config, SCOPES)
            creds = flow.run_local_server(port=0, open_browser=False)
        with open('RetrievalParsing/secrets/token.json', 'w') as token_file:
            token_file.write(creds.to_json())

    return creds

def extract_urls(text):
    # Match http(s)://... or www... (not already inside quotes, angle brackets, or parentheses)
    url_regex = re.compile(
        r'\b(?:https?://|www\.)'       # protocol or www
        r'[-a-zA-Z0-9@:%._\+~#=]{2,256}'  # domain name
        r'\.[a-z]{2,24}'               # TLD
        r'\b(?:[-a-zA-Z0-9@:%_\+.~#?&/=]*)',  # path/query
        re.IGNORECASE
    )
    return url_regex.findall(text)

def setup_db():
    conn = sqlite3.connect("emails.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id TEXT PRIMARY KEY,
            thread_id TEXT,
            subject TEXT,
            sender TEXT,
            date TEXT,
			body TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS attachments (
            email_id TEXT,
            filename TEXT,
            mime_type TEXT,
            data BLOB,
            FOREIGN KEY(email_id) REFERENCES emails(id)
        )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS urls (
        email_id TEXT,
        url TEXT,
        FOREIGN KEY(email_id) REFERENCES emails(id)
        )
    ''')
    conn.commit()
    return conn

def get_email_metadata(headers, name):
    for h in headers:
        if h['name'].lower() == name.lower():
            return h['value']
    return ""

def extract_body(payload):
    if 'body' in payload and 'data' in payload['body']:
        return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='replace')

    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain' and 'data' in part.get('body', {}):
                return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='replace')
            elif part['mimeType'].startswith('multipart/'):
                result = extract_body(part)
                if result:
                    return result
    return ''

def save_email(conn, email, service):
    payload = email['payload']
    headers = payload.get('headers', [])
    email_id = email['id']
    thread_id = email['threadId']
    subject = get_email_metadata(headers, 'Subject')
    sender = get_email_metadata(headers, 'From')
    date = get_email_metadata(headers, 'Date')
    body = extract_body(payload)
    urls = extract_urls(body)
    
    c = conn.cursor()
    c.execute('''
        INSERT OR IGNORE INTO emails (id, thread_id, subject, sender, date, body)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (email_id, thread_id, subject, sender, date, body))

    parts = payload.get('parts', [])
    for part in parts:
        if part.get('filename'):
            att_id = part['body'].get('attachmentId')
            if att_id:
                attachment = service.users().messages().attachments().get(
                    userId='me',
                    messageId=email_id,
                    id=att_id
                ).execute()
                data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
                c.execute('''
                    INSERT INTO attachments (email_id, filename, mime_type, data)
                    VALUES (?, ?, ?, ?)
                ''', (email_id, part['filename'], part['mimeType'], data))

    for url in urls:
        c.execute('INSERT INTO urls (email_id, url) VALUES (?, ?)', (email_id, url))
    if urls:
        print(f"\033[32mEmail with subject: \"{subject}\" has {len(urls)} URL(s):\033[0m")
        for url in urls:
            print(f"  → {url}")

    conn.commit()

def fetch_and_store_emails(creds):
    try:
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
        messages = results.get('messages', [])

        if not messages:
            print("No messages found.")
            return

        conn = setup_db()

        for msg in messages:
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            save_email(conn, email, service)

        print("Emails and attachments stored in emails.db.")

    except HttpError as error:
        print(f"An error occurred: {error}")

if __name__ == '__main__':
    creds = authorize()
    fetch_and_store_emails(creds)
