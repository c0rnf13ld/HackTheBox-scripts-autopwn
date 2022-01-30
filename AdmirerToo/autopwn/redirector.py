#!/usr/bin/python3

import http.server, sys, signal, argparse

def args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-l", "--listener", help="The ip to listen on, by default: 0.0.0.0", default="0.0.0.0")
	parser.add_argument("-u", "--url", help="The url to redirect to", required=True)
	args = parser.parse_args()
	return args.listener, args.url

def redirector(url):
	class MakeRedirect(http.server.BaseHTTPRequestHandler):
		def do_GET(self):
			self.send_response(301)
			self.send_header('Location', url)
			self.end_headers()

		def do_POST(self):
			self.send_response(301)
			self.send_header('Location', url)
			self.end_headers()
	return MakeRedirect

def initServer(host, port, url):
	global s
	handler = redirector(url)
	with http.server.HTTPServer((host, port), handler) as s:
		print(f"Serving HTTP on {host} port {port} (http://{host}:{port}/) ...")
		s.serve_forever()

def main():
	host, url = args()
	port = 80
	initServer(host, port, url)

def def_handler(signum, frame):
	print("\n\n[*] Exiting...\n")
	s.server_close()
	sys.exit()

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
	main()
