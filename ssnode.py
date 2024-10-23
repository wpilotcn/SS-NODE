import requests
import base64
import json
import pyaes
import binascii
from datetime import datetime
import argparse
import schedule
import time

def decrypt_data(encrypted_data, key, iv):
    cipher = pyaes.AESModeOfOperationCBC(key, iv=iv)
    decrypted = b''.join(cipher.decrypt(encrypted_data[j:j+16]) for j in range(0, len(encrypted_data), 16))
    return decrypted[:-decrypted[-1]]

def main(data):
    output_lines = []
    output_lines.append("      H͜͡E͜͡L͜͡L͜͡O͜͡ ͜͡W͜͡O͜͡R͜͡L͜͡D͜͡ ͜͡E͜͡X͜͡T͜͡R͜͡A͜͡C͜͡T͜͡ ͜͡S͜͡S͜͡ ͜͡N͜͡O͜͡D͜͡E͜͡")
    output_lines.append("𓆝 𓆟 𓆞 𓆟 𓆝 𓆟 𓆞 𓆟 𓆝𓆝 𓆟𓆝 𓆟 𓆟 𓆞 𓆟")
    output_lines.append("Author : wpilot")
    output_lines.append(f"Date   : {datetime.today().strftime('%Y-%m-%d')}")
    output_lines.append("Version: 1.0")
    output_lines.append("𓆝 𓆟 𓆞 𓆟 𓆝 𓆟 𓆞 𓆟 𓆝 𓆟𓆝 𓆟𓆝 𓆟 𓆞 𓆟")

    a = 'http://api.skrapp.net/api/serverlist'
    b = {
        'accept': '/',
        'accept-language': 'zh-Hans-CN;q=1, en-CN;q=0.9',
        'appversion': '1.3.1',
        'user-agent': 'SkrKK/1.3.1 (iPhone; iOS 13.5; Scale/2.00)',
        'content-type': 'application/x-www-form-urlencoded',
        'Cookie': 'PHPSESSID=fnffo1ivhvt0ouo6ebqn86a0d4'
    }
    c = {'data': data}
    d = b'65151f8d966bf596'
    e = b'88ca0f0ea1ecf975'

    j = requests.post(a, headers=b, data=c)

    if j.status_code == 200:
        k = j.text.strip()
        l = binascii.unhexlify(k)
        m = decrypt_data(l, d, e)
        n = json.loads(m)
        for o in n['data']:
            p = f"aes-256-cfb:{o['password']}@{o['ip']}:{o['port']}"
            q = base64.b64encode(p.encode('utf-8')).decode('utf-8')
            r = f"ss://{q}#{o['title']}"
            output_lines.append(r)

    # Write to TXT file, replacing existing content
    with open('output.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(output_lines))

def job():
    # Replace 'your_data' with the actual data you need to process
    data = 'your_data'
    main(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some data.')
    parser.add_argument('--data', type=str, required=True, help='Data to process')
    args = parser.parse_args()

    # Schedule the job every 12 hours
    schedule.every(12).hours.do(job)

    # Run the job immediately
    job()

    while True:
        schedule.run_pending()
        time.sleep(1)
