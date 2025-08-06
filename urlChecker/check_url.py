import sqlite3
from checker import IPQS, GoogleSafeBrowsing  

IPQS_API_KEY = 'your_ipqs_key'
GSB_API_KEY = 'your_gsb_key'

ipqs = IPQS(api_key=IPQS_API_KEY)
gsb = GoogleSafeBrowsing(api_key=GSB_API_KEY)

conn = sqlite3.connect('emails.db')
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS url_checks (
        url TEXT PRIMARY KEY,
        email_id TEXT,
        is_safe INTEGER,
        ipqs_result INTEGER,
        gsb_result INTEGER,
        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(email_id) REFERENCES emails(id)
    )
''')

c.execute('SELECT id FROM emails ORDER BY rowid ASC LIMIT 1')
email_row = c.fetchone()

if email_row:
    email_id = email_row[0]
    print(f"📧 Scanning email ID: {email_id}")

    c.execute('SELECT url FROM urls WHERE email_id = ?', (email_id,))
    urls = c.fetchall()

    for (url,) in urls:

        c.execute('SELECT url FROM url_checks WHERE url = ?', (url,))
        if c.fetchone():
            print(f"⏩ Already scanned: {url}")
            continue

        print(f"🔍 Checking URL: {url}")
        ipqs_result = int(ipqs.check_url(url))
        gsb_result = int(gsb.check_url(url))
        is_safe = int(ipqs_result and gsb_result)

        c.execute('''
            INSERT OR REPLACE INTO url_checks (url, email_id, is_safe, ipqs_result, gsb_result)
            VALUES (?, ?, ?, ?, ?)
        ''', (url, email_id, is_safe, ipqs_result, gsb_result))
        conn.commit()

    print("✅ Done checking URLs for this email.")
else:
    print("⚠️ No emails found in database.")

conn.close()
