"""

Implements communication protocol
-for privacy-preserving data analytics
-using zeromq for messaging, and json and base64 for representation/parsing.
		        
Author: Shagufta Mehnaz, shagufta.mehnaz@hpe.com

"""

import zmq
import csv
import json
import numpy
import base64
import sys
import random
import time
import long_matrix
#from paillier.paillier import *
# from long_matrix import *



MSG_LIST= [	"MSG_FAILURE",
	"MSG_TERM_COMP",
	"MSG_TERM_ALL",
	"MSG_KEY_MEDIATOR_NODE",
	"MSG_KEY_NODE_MEDIATOR",
	"MSG_KEYS_MEDIATOR_NODE",
	"MSG_EDATA_NODE_MEDIATOR",
	"MSG_EDATA_MEDIATOR_NODE",
	"MSG_DSTATA_NODE_NODE",
	"MSG_DSTATA_NODE_MEDIATOR",
	"MSG_PARTIES_MEDIATOR_NODE",
	"MSG_CSRDATA_NODE_MEDIATOR",
   	"MSG_CSRDATA_MEDIATOR_LNODE",
   	"MSG_DSDATA_FNODE_MEDIATOR",
	"MSG_THETA_MEDIATOR_NODE",
	"MSG_GRADIENT_COST_NODE_MEDIATOR",
	"MSG_RAWDATAX_NODE_MEDIATOR",
	"MSG_RAWDATAY_NODE_MEDIATOR",
	"MSG_LOCAL_H_THETA_NODE_MEDIATOR",
	"MSG_GLOBALSUM_MEDIATOR_NODE",
	"MSG_RAND_NODE_MEDIATOR",
	"MSG_RAND_MEDIATOR_NODE",
	"MSG_LOCAL_NODE_MEDIATOR"]



MSG_FAILURE = "00"
MSG_TERM_COMP = "01"
MSG_TERM_ALL = "02"
MSG_KEY_MEDIATOR_NODE = "03"
MSG_KEY_NODE_MEDIATOR = "04"
MSG_KEYS_MEDIATOR_NODE = "05"
MSG_EDATA_NODE_MEDIATOR = "06"
MSG_EDATA_MEDIATOR_NODE = "07"
MSG_DSTATA_NODE_NODE = "08"
MSG_DSTATA_NODE_MEDIATOR = "09"
MSG_PARTIES_MEDIATOR_NODE = "10"
MSG_CSRDATA_NODE_MEDIATOR = "11"
MSG_CSRDATA_MEDIATOR_LNODE = "12"
MSG_DSDATA_FNODE_MEDIATOR = "13"
MSG_THETA_MEDIATOR_NODE = "14"
MSG_GRADIENT_COST_NODE_MEDIATOR = "15"
MSG_RAWDATAX_NODE_MEDIATOR = "16"
MSG_RAWDATAY_NODE_MEDIATOR = "17"
MSG_LOCAL_H_THETA_NODE_MEDIATOR = "18"
MSG_GLOBALSUM_MEDIATOR_NODE = "19"

MSG_RAND_NODE_MEDIATOR = "20"
MSG_RAND_MEDIATOR_NODE = "21"
MSG_LOCAL_NODE_MEDIATOR = "22"




debug_by_sm = False # print debug info; boolean
cryptosystem = 0 # 0: elgamal, 1: paillier




class ParsingError(RuntimeError):
	def __init__(self, arg):
		self.args = arg



def pack_vector(u):
	"""
		Packs a numpy vector/array
	"""
	msg = base64.b64encode(u.tostring())

	return msg

def parse_vector(content):
	"""
		Parses a numpy vector/array
	"""
	try:
		u = numpy.fromstring(base64.b64decode(content))
	except:
		print >> sys.stderr, "Parsing error."
		print >> sys.stderr, "Content: ", content
		raise ParsingError("")

	return u

def pack_matrix(R):
	"""
		Packs a matrix
	"""
	msg = base64.b64encode(R.tostring())

	return msg

def parse_matrix(content):
	"""
		Parses a matrix
	"""
	try:
		R = numpy.fromstring(base64.b64decode(content))
	except:
		print >> sys.stderr, "Parsing error."
		print >> sys.stderr, "Content: ", content
		raise ParsingError("")

	return R

def pack_vector_smc(R):
	"""
		Packs a vector of longs
	"""
	msg = ""
	for i in range(len(R)):
		msg = msg + "," + str(R[i])

	return msg[1:]

def parse_vector_smc(content):
	"""
		Parses a vector of longs
	"""
	vec = content.split(',')
	R = []

	if vec[0] != '':
		for p in range(len(vec)):
			#R.append(float(vec[p]))
			R.append(long(vec[p]))

	return R

def pack_3D_matrix_smc(R):
	"""
		Packs a 3D matrix of longs
	"""
	msg = ""
	for i in range(len(R)):
		for j in range(len(R[0])):
			for k in range(len(R[0][0])):
				msg = msg + "," + str(R[i][j][k])

	return msg[1:]

def pack_2D_matrix_smc(R):
	"""
		Packs a 2D matrix of longs
	"""
	msg = ""
	for i in range(len(R)):
		for j in range(len(R[0])):
			msg = msg + "," + str(R[i][j])

	return msg[1:]

def parse_3D_matrix_smc(content, l, num_shares):
	"""
		Parses a 3D matrix of longs
	"""
	vec = content.split(',')

	num_cols = int(float(len(vec)) / (l * num_shares))

	R = long_matrix.matrix_zeros_3D(l, num_cols, num_shares)

	i = 0
	j = 0
	k = 0

	if vec[0] != '':
		for p in range(len(vec)):
			#R[i][j][k] = float(vec[p])
			R[i][j][k] = long(vec[p])
			k = k + 1

			if k == num_shares:
				j = j + 1
				k = 0
				if j == num_cols:
					i = i + 1
					j = 0
	return R

def parse_2D_matrix_smc(content, l):
	"""
		Parses a 2D matrix of longs
	"""
	vec = content.split(',')
	num_cols = int(float(len(vec)) / l)
	R = long_matrix.matrix_zeros_2D(l, num_cols)

	i = 0
	j = 0
	if vec[0] != '':
		for p in range(len(vec)):
			R[i][j] = long(vec[p])
			#R[i][j] = float(vec[p])
			j = j + 1

			if j == num_cols:
				i = i + 1
				j = 0
	return R

def pack_msg(_type, _id, _content, src, dest):
	"""
		Generic message packing using json.
	"""
	msg = {}
	#msg['comp'] = _comp
	msg['type'] = _type
	msg['id'] = _id
	msg['content'] = _content
	msg['src'] = src
	msg['dest'] = dest

	return json.dumps(msg)








