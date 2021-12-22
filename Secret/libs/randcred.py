#!/usr/bin/python3

import random as rand
from random import *
from string import *

class Generator():
	def __init__(self, length=10, char=True, digit=False, special=False, all=False):
		# Booleans
		self.length = int(length)
		self.char = char
		self.special = special
		self.digits = digit
		self.all = all

		# Strings
		self.string_only = ascii_letters
		self.digits_only = digits
		self.special_char = punctuation
		self.all_values = self.string_only + self.digits_only + self.special_char

	def genRandStr(self):
		self.rand_value = ""
		for i in range(self.length):
			if self.all:
				self.rand_value += choice(self.all_values)

			elif self.special:
				if self.char:
					if self.digits:
						self.rand_value += choice(self.string_only + self.digits_only + self.special_char)
					else:
						self.rand_value += choice(self.string_only + self.special_char)
				else:
					if self.digits:
						self.rand_value += choice(self.digits_only + self.special_char)

			elif self.char:
				if self.digits:
					self.rand_value += choice(self.string_only + self.digits_only)
				else:
					self.rand_value += choice(self.string_only)

			elif self.digits:
				if self.char:
					self.rand_value += choice(self.digits_only + self.string_only)
				else:
					self.rand_value += choice(self.digits_only)

		return self.rand_value

if __name__ == '__main__':
	generator = Generator(length=30, digit=True, char=False, special=True)
	rand_value = generator.genRandStr()
	print(f"The key is: {rand_value} with length of: {len(rand_value)}")
	print(f"Is alpha: {rand_value.isalpha()}")
	print(f"Is alphanumeric: {rand_value.isalnum()}")
	print(f"Is numeric: {rand_value.isnumeric()}")