"""

Implements privacy-preserving protocols and evaluation.

Author: Shagufta Mehnaz, shagufta.mehnaz@hpe.com

"""

import random
import csv
import numpy
import math
import sys
#import kmeans
from numpy import linalg
# from paillier.paillier import *
# from long_matrix import *
from sklearn import *
import re

import paillier
import elgamal
import comm
import long_matrix


class SMC(object):
	"""
		Secure multiparty computation
	"""

	def __init__(self, _max_val, _prec):
		"""

		"""
		self.n_bits = 128

		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			elgamal_keys = elgamal.generate_keys(self.n_bits, 32)
			self.priv = elgamal_keys['privateKey']
			self.pub = elgamal_keys['publicKey']
			self.med_key = elgamal_keys
			#############################################

		elif comm.cryptosystem == 1:
			#############################################
			# PAILLIER CRYPTOSYSTEM
			self.priv, self.pub = paillier.generate_keypair(self.n_bits)
			self.med_key = self.priv, self.pub
			#############################################

		self.node_keys = []
		self.shares = []
		self.max_val = _max_val
		self.prec = _prec
		self.mask_value = random.randint(1, _max_val + 1)



	def set_mediator_key(self, med_key):
		"""
			Stores mediator public key (Node function)
		"""
		if comm.debug_by_sm == True:
			print 'set_mediator_key:'

		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			key_params = med_key.split('|')
			if comm.debug_by_sm == True:
				print key_params
			self.med_key = elgamal.PublicKey(int(key_params[0]), int(key_params[1]), int(key_params[2]), int(key_params[3]))
			#############################################

		elif comm.cryptosystem == 1:
			#############################################
			# PAILLIER CRYPTOSYSTEM
			self.med_key = paillier.PublicKey(int(med_key))
			#############################################



	def set_nodes_public_keys(self, keys):
		"""
			Stores all nodes public keys (Node function)
		"""
		if comm.debug_by_sm == True:
			print 'set_nodes_public_keys:'

		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			for i in range(len(keys)):
				key_params = keys[i].split('|')
				if comm.debug_by_sm == True:
					print key_params
				one_node_key = elgamal.PublicKey(int(key_params[0]), int(key_params[1]), int(key_params[2]), int(key_params[3]))
				self.node_keys.append(one_node_key)
			#############################################

		elif comm.cryptosystem == 1:
			#############################################
			# PAILLIER CRYPTOSYSTEM
			for i in range(len(keys)):
				self.node_keys.append(paillier.PublicKey(int(keys[i])))
			#############################################



	def set_shares(self, number_of_data_segments):
		"""
			Sets share ratios (Node function)
		"""
		s = 0
		self.shares = []
		for i in range(number_of_data_segments):
			self.shares.append(random.random())
			s = s + self.shares[-1]

		for i in range(number_of_data_segments):
			self.shares[i] = float(self.shares[i]) / s

		if comm.debug_by_sm == True:
			print 'shares:'
			for i in range(number_of_data_segments):
				print self.shares[i]


	def compute_data_segments(self, data, number_of_data_segments):

		segmented_data = []

		for i in range(len(data)):
			segmented_one_data = []
			self.set_shares(number_of_data_segments)
			for j in range(len(self.shares)):
				segmented_one_data.append(data[i]*self.shares[j])
			segmented_data.append(segmented_one_data)

		return segmented_data



	def encrypt_data_segments(self, segmented_data):
		"""
			Encrypts random shares for centroids and counts,
			each based on the public key of its particular receiver
		"""
		# Format [  [share 1 dim 1, share 2 dim 1, .. share m dim 1]
		#           ....
		#           [share 1 dim d, share 2 dim d, .. share m dim d]  ]
		encrypted_segmented_data = long_matrix.matrix_zeros_2D(len(segmented_data), len(segmented_data[0]))


		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			if comm.debug_by_sm == True:
				print '\n\nencrypt_data_segments'
				print len(segmented_data)
				print len(segmented_data[0])
			for i in range(len(segmented_data)): #number of dimensions
				mod_value = i % len(self.node_keys) #if num of parties 4, mod_value: 0,1,2,3,0,1,2,3,...
				for j in range(len(segmented_data[0])): #number of shares
					encrypted_data_share = elgamal.encrypt(self.med_key, unicode(str(segmented_data[i][j])))
					# if i==0 and j==0:
					if comm.debug_by_sm == True:
						print segmented_data[i][j]
						print i, j
						print encrypted_data_share
					for k in range(len(self.node_keys)):
						l = (k + mod_value) % len(self.node_keys)
						# if mod_value = 2, (for dimension 2, 6, ...)
						# l = (0+2)%4 = 2
						# l = (1+2)%4 = 3
						# l = (2+2)%4 = 0
						# l = (3+2)%4 = 1

						if comm.debug_by_sm == True:
							print 'l: ' + str(l)
						encrypted_data_share = elgamal.encrypt(self.node_keys[l], unicode(str(encrypted_data_share)))
						#if i == 0 and j == 0:

						# if comm.debug_by_sm == True:
						#     if k==0:
						#         print encrypted_data_share
					encrypted_segmented_data[i][j] = encrypted_data_share
			#############################################

		elif comm.cryptosystem == 1:
			#############################################
			# PAILLIER CRYPTOSYSTEM
			if comm.debug_by_sm == True:
				print '\n\nencrypt_data_segments'
				print len(segmented_data)
				print len(segmented_data[0])
			for i in range(len(segmented_data)): #number of dimensions
				mod_value = i % len(self.node_keys) #if num of parties 4, mod_value: 0,1,2,3,0,1,2,3,...
				for j in range(len(segmented_data[0])): #number of shares
					encrypted_data_share = paillier.encrypt(self.med_key, long(segmented_data[i][j]))

					# if i==0 and j==0:
					if comm.debug_by_sm == True:
						print segmented_data[i][j]
						print i, j
						print encrypted_data_share

					for k in range(len(self.node_keys)):
						l = (k + mod_value) % len(self.node_keys)

						if comm.debug_by_sm == True:
							print 'l: ' + str(l)

						encrypted_data_share = paillier.encrypt(self.node_keys[l], long(encrypted_data_share))
						#if i == 0 and j == 0:
						#if k==0:
						# print encrypted_data_share
					encrypted_segmented_data[i][j] = encrypted_data_share
			#############################################


		# print 'encrypted_segmented_data'
		# print encrypted_segmented_data

		return  encrypted_segmented_data



	def encrypt_aggregated_data(self, aggregated_data):
		"""
			Encrypts aggregated data
		"""
		# Format [aggregated share 1, aggregated share 2, .. aggregated share m]
		encrypted_aggregated_data = [None]*len(aggregated_data)


		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM

			for i in range(len(aggregated_data)): #number of shares
				encrypted_aggregated_data_share = elgamal.encrypt(self.med_key, unicode(str(aggregated_data[i])))
				# if i==0:
					# print aggregated_data[i]
					# print encrypted_aggregated_data_share
				for k in range(len(self.node_keys)):
					encrypted_aggregated_data_share = elgamal.encrypt(self.node_keys[k], unicode(str(encrypted_aggregated_data_share)))
					# if i ==0:
						# print encrypted_aggregated_data_share
				encrypted_aggregated_data[i] = encrypted_aggregated_data_share
			#############################################


		return  encrypted_aggregated_data



	def encrypt_aggregated_data_linear_cipher_growth(self, aggregated_data, byte_to_encrypt):
		"""
			Encrypts aggregated data
		"""
		# Format [aggregated share 1, aggregated share 2, .. aggregated share m]
		encrypted_aggregated_data = [None]*len(aggregated_data)


		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM

			for i in range(len(aggregated_data)): #number of shares
				encrypted_aggregated_data_share = elgamal.encrypt(self.med_key, unicode(str(aggregated_data[i])))
				# if i==0:
				#     print aggregated_data[i]
				#     print encrypted_aggregated_data_share
				for k in range(len(self.node_keys)):
					encrypted_aggregated_data_share = elgamal.encrypt(self.node_keys[k], unicode(str(encrypted_aggregated_data_share[:byte_to_encrypt]))) + '|' + str(encrypted_aggregated_data_share[byte_to_encrypt:])
					# if i ==0:
					#     print encrypted_aggregated_data_share
				encrypted_aggregated_data[i] = encrypted_aggregated_data_share
			#############################################


		return  encrypted_aggregated_data


	def encrypt_ratios(self, dimension_ratios_for_shares):
		"""
			Encrypts aggregated data
		"""
		# Format [aggregated share 1, aggregated share 2, .. aggregated share m]
		encrypted_dimension_ratios_for_shares = [None]*len(dimension_ratios_for_shares)


		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM

			for i in range(len(dimension_ratios_for_shares)): #number of dimensions
				encrypted_aggregated_data_share = elgamal.encrypt(self.med_key, unicode(str(dimension_ratios_for_shares[i])))
				# if i==0 and j==0:
				#if comm.debug_by_sm == True:
				# print dimension_ratios_for_shares[i]
				# print i
				# print encrypted_aggregated_data_share
				for k in range(len(self.node_keys)):
					encrypted_aggregated_data_share = elgamal.encrypt(self.node_keys[k], unicode(str(encrypted_aggregated_data_share)))
					# print encrypted_aggregated_data_share
				encrypted_dimension_ratios_for_shares[i] = encrypted_aggregated_data_share
			#############################################


		return  encrypted_dimension_ratios_for_shares





	def encrypt_ratios_linear_cipher_growth(self, dimension_ratios_for_shares, byte_to_encrypt):
		"""
			Encrypts aggregated data
		"""
		# Format [aggregated share 1, aggregated share 2, .. aggregated share m]
		encrypted_dimension_ratios_for_shares = [None]*len(dimension_ratios_for_shares)


		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM

			for i in range(len(dimension_ratios_for_shares)): #number of dimensions
				encrypted_aggregated_data_share = elgamal.encrypt(self.med_key, unicode(str(dimension_ratios_for_shares[i])))
				# if i==0 and j==0:
				#if comm.debug_by_sm == True:
				# print dimension_ratios_for_shares[i]
				# print i
				# print encrypted_aggregated_data_share
				for k in range(len(self.node_keys)):
					encrypted_aggregated_data_share = elgamal.encrypt(self.node_keys[k], unicode(str(encrypted_aggregated_data_share[:byte_to_encrypt]))) + '|' + str(encrypted_aggregated_data_share[byte_to_encrypt:])
					# print encrypted_aggregated_data_share
				encrypted_dimension_ratios_for_shares[i] = encrypted_aggregated_data_share
			#############################################


		return  encrypted_dimension_ratios_for_shares



	def decrypt_n_shuffle(self, data_to_decrypt_n_shuffle, number_of_parties):

		# decrypt
		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			for i in range(len(data_to_decrypt_n_shuffle)):
				for j in range(len(data_to_decrypt_n_shuffle[0])):

					data_to_decrypt_n_shuffle[i][j] = elgamal.decrypt(self.priv, data_to_decrypt_n_shuffle[i][j])
			#############################################

		elif comm.cryptosystem == 1:
			#############################################
			# PAILLIER CRYPTOSYSTEM
			for i in range(len(data_to_decrypt_n_shuffle)):
				for j in range(len(data_to_decrypt_n_shuffle[0])):
					data_to_decrypt_n_shuffle[i][j] = paillier.decrypt(self.priv, self.pub, long(data_to_decrypt_n_shuffle[i][j]))
			#############################################

		# shuffle
		#               #           #   [party1, share1]   [party1, share2]
		#  1st attrb.   # 3 parties #   [party2, share1]   [party2, share2]
		#               #           #   [party3, share1]   [party3, share2]
		#               #           #   [party1, share1]   [party1, share2]
		#  2nd attrb.   # 3 parties #   [party2, share1]   [party2, share2]
		#               #           #   [party3, share1]   [party3, share2]
		#
		#
		#  #attributes
		#       *
		#  # parties
		#
		#
		#
		#
		number_of_attributes_handled = len(data_to_decrypt_n_shuffle)/number_of_parties
		for k in range(number_of_attributes_handled):
			data_to_shuffle = []
			for i in range(k*number_of_parties, (k+1)*number_of_parties):
				for j in range(len(data_to_decrypt_n_shuffle[0])):
					data_to_shuffle.append(data_to_decrypt_n_shuffle[i][j])
			# if k ==0:
			#     print 'data_to_shuffle before shuffling'
			#     print data_to_shuffle
			random.shuffle(data_to_shuffle)
			# if k==0:
			#     print 'after shuffling'
			#     print data_to_shuffle
			l=0
			for i in range(k*number_of_parties, (k+1)*number_of_parties):
				for j in range(len(data_to_decrypt_n_shuffle[0])):
					data_to_decrypt_n_shuffle[i][j] = data_to_shuffle[l]
					l+=1
			# if k ==0:
			#     for i in range(k*number_of_parties, (k+1)*number_of_parties):
			#         for j in range(len(data_to_decrypt_n_shuffle[0])):
			#             print data_to_decrypt_n_shuffle[i][j]



		return data_to_decrypt_n_shuffle



	def decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(self, data_to_decrypt_n_shuffle, number_of_parties):

		# decrypt
		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			for i in range(len(data_to_decrypt_n_shuffle)):
				for j in range(len(data_to_decrypt_n_shuffle[0])):
					for k in range(len(data_to_decrypt_n_shuffle[0][0])):
						index_up_to_decrypt = data_to_decrypt_n_shuffle[i][j][k].index('|')
						one_data_to_decrypt_n_shuffle = data_to_decrypt_n_shuffle[i][j][k][:index_up_to_decrypt]
						data_to_decrypt_n_shuffle[i][j][k] = elgamal.decrypt(self.priv, one_data_to_decrypt_n_shuffle) + data_to_decrypt_n_shuffle[i][j][k][index_up_to_decrypt+1:]
			#############################################

		elif comm.cryptosystem == 1:
			#############################################
			# PAILLIER CRYPTOSYSTEM
			for i in range(len(data_to_decrypt_n_shuffle)):
				for j in range(len(data_to_decrypt_n_shuffle[0])):
					data_to_decrypt_n_shuffle[i][j] = paillier.decrypt(self.priv, self.pub, long(data_to_decrypt_n_shuffle[i][j]))
			#############################################



		#TODO: shuffle

		return data_to_decrypt_n_shuffle



	def decrypt_n_shuffle_combined_share_ratios(self, data_to_decrypt_n_shuffle, number_of_parties):

		# decrypt
		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			for i in range(len(data_to_decrypt_n_shuffle)):
				for j in range(len(data_to_decrypt_n_shuffle[0])):
					for k in range(len(data_to_decrypt_n_shuffle[0][0])):
						data_to_decrypt_n_shuffle[i][j][k] = elgamal.decrypt(self.priv, data_to_decrypt_n_shuffle[i][j][k])
			#############################################

		elif comm.cryptosystem == 1:
			#############################################
			# PAILLIER CRYPTOSYSTEM
			for i in range(len(data_to_decrypt_n_shuffle)):
				for j in range(len(data_to_decrypt_n_shuffle[0])):
					data_to_decrypt_n_shuffle[i][j] = paillier.decrypt(self.priv, self.pub, long(data_to_decrypt_n_shuffle[i][j]))
			#############################################



		#TODO: shuffle

		return data_to_decrypt_n_shuffle

	def compute_sum_smc_v1(self, number_of_dimensions, number_of_data_segments, data_decrypted_from_all_nodes, parties):
		global_sum = []
		for current_dim in range(number_of_dimensions):
			# get party number
			party_no = current_dim % len(parties)
			current_dim_global_sum = 0
			start_index = (current_dim / len(parties)) * len(parties)
			end_index = start_index + len(parties)

			if comm.cryptosystem == 0:
				#############################################
				# ELGAMAL CRYPTOSYSTEM
				for party_row_index in range(start_index, end_index):
					for shard_no in range(number_of_data_segments):
						current_dim_global_sum = current_dim_global_sum + float(elgamal.decrypt(self.priv,
																								data_decrypted_from_all_nodes[
																									parties[party_no]][
																									party_row_index][
																									shard_no]))
				#############################################

			elif comm.cryptosystem == 1:
				#############################################
				# PAILLIER CRYPTOSYSTEM
				for party_row_index in range(start_index, end_index):
					for shard_no in range(number_of_data_segments):
						current_dim_global_sum = current_dim_global_sum + float(paillier.decrypt(self.priv, self.pub,
																								long(data_decrypted_from_all_nodes[
																									parties[party_no]][
																									party_row_index][
																									shard_no])))
				#############################################


			global_sum.append(current_dim_global_sum)

		return global_sum



	def compute_sum_smc_v2(self, number_of_dimensions, number_of_data_segments, data_decrypted_from_all_nodes, parties):

		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			for i in range(len(data_decrypted_from_all_nodes)): # number of parties
				for j in range(len(data_decrypted_from_all_nodes[0])): # number of shares
					for k in range(len(data_decrypted_from_all_nodes[0][0])): # always 2: sum and ratios
						data_decrypted_from_all_nodes[i][j][k] = elgamal.decrypt(self.priv, data_decrypted_from_all_nodes[i][j][k])
						# print data_decrypted_from_all_nodes[i][j][k]
			#############################################

		share_wise_values = []
		# print '\n\n'
		for i in range(len(data_decrypted_from_all_nodes)):
			for j in range(len(data_decrypted_from_all_nodes[0])):
				# print i, j
				value = float(data_decrypted_from_all_nodes[i][j][0])
				ratio_list_whole = str(data_decrypted_from_all_nodes[i][j][1])[1:len(str(data_decrypted_from_all_nodes[i][j][1]))-1]
				ratio_list = ratio_list_whole.split(', ')
				for k in range(len(ratio_list)):
					ratio_list[k] = float(ratio_list[k])
				for k in range(len(ratio_list)):
					ratio_list[k] = float(ratio_list[k])*value
				# print value
				# print ratio_list
				share_wise_values.append(ratio_list)

		global_sum = [0] * number_of_dimensions
		for i in range(number_of_dimensions):
			for j in range(len(parties)*number_of_data_segments):
				global_sum[i] += share_wise_values[j][i]

		return global_sum

	####################################################################################
	###################################   ssum_v3   ####################################
	####################################################################################


	def encrypt_random_numbers(self, random_nums):
		encrypted_random_numbers = long_matrix.matrix_zeros_2D(len(random_nums), len(random_nums[0]))

		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			for i in range(len(random_nums)):  #number of other parties
				#mod_value = i % len(self.node_keys) #if num of parties 4, mod_value: 0,1,2,3,0,1,2,3,...
				for j in range(len(random_nums[0])):  #number of values for sum
					encrypted_random_numbers[i][j] = elgamal.encrypt(self.node_keys[i], unicode(str(random_nums[i][j])))

		# print 'encrypted_random_numbers'
		# print encrypted_random_numbers

		return encrypted_random_numbers


	def decrypt_random_numbers(self, random_numbers_to_decrypt):

		# decrypt
		decrypted_random_numbers = [None] * len(random_numbers_to_decrypt)
		if comm.cryptosystem == 0:
			#############################################
			# ELGAMAL CRYPTOSYSTEM
			# print 'decrypt_random_numbers', len(random_numbers_to_decrypt)
			for i in range(len(random_numbers_to_decrypt)):
				# print 'lalala'
				# print 'messge to decrypt', random_numbers_to_decrypt[i]
				decrypted_random_numbers[i] = elgamal.decrypt(self.priv, random_numbers_to_decrypt[i]) #[:len(str(random_numbers_to_decrypt[i]))-1]
				# print decrypted_random_numbers[i]
				#############################################
		return decrypted_random_numbers










