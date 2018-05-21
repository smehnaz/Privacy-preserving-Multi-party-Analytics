"""

Secure Sum Implementation

Author: Shagufta Mehnaz, shagufta.mehnaz@hpe.com

"""

import zmq
import sys
import getopt
import time
import comm
import comm_mediator_sec_sum
import comm_node_sec_sum
import privacy
import elgamal
import paillier
import long_matrix
import numpy as np
import time
import math
import random


def print_parameters(mediator, hname, port, num_nodes, num_dim, num_samples, num_shares, mediator_node, precision_digits, file_name, lin_log_input, ssum_version, onion_encrypt_bytes, partition_type, mini_batch_size):
	"""
	"""
	print "mediator = ", mediator
	print "hostname = ", hname
	print "port = ", port
	print "num_nodes = ", num_nodes
	print "num_dimensions = ", num_dim
	print "num_samples = ", num_samples
	print "num_shares = ", num_shares
	print "mediator_node = ", mediator_node
	print "precision = ", precision_digits
	print "filename(I/O) = ", file_name
	print "data analytics: linear/logistic regression(1/2) = ", lin_log_input
	print "ssum version(1/2) =  ", ssum_version
	print "re-encryption bytes = ", onion_encrypt_bytes
	print "partition type = ", partition_type
	print "mini batch size = ", mini_batch_size


def print_usage():
	"""
	"""
	print "Secure Sum Implementation"
	print "Usage: python secure_sum_impl.py [arguments]"
	print "Arguments:"

	print "	-m Run as mediator"
	print "	-n <string>		Host name"
	print "	-r <integer>	Port"
	print "	-u <integer>	Number of data nodes"
	print "	-d <integer>	Number of dimensions"
	print " -p <integer>	Number of samples"
	print "	-s <integer>	Number of data shares"
	print "	-y <string>	Mediator host"
	print " -c <integer> Precision"
	print " -f <string> File name"
	print " -o <integer> Operation(1=Linear regression/2=Logistic Regression)"
	print " -v <integer> SSum version(1/2)"
	print " -b <integer> Re-encryption bytes"
	print " -t <integer> Partition type"
	print " -i <integer> Batch size"
	print "	-h 		Help"


class Usage(Exception):
	"""
	"""
	def __init__(self, msg):
		"""
		"""
		print_usage()
		self.msg = msg


def main(argv=None):
	"""
	"""

	if argv is None:
		argv = sys.argv


	try:
		try:
			opts, input_files = getopt.getopt(argv[1:], "n:r:u:d:p:s:y:c:f:o:v:b:t:i:mh", ["host", "port", "num-nodes", "num-dimensions", "num-samples", "num-shares", "mediator-host", "precision", "file-name", "operation-lin-log", "ssum-version", "reencryption-bytes", "mediator", "partition-type", "batch-size", "help"])
		except getopt.error, msg:
			raise Usage(msg)



		hname= ""
		port= ""
		num_nodes = 0
		number_of_dimensions = 0
		number_of_samples = 0
		number_of_data_segments = 0
		mediator_node = ""
		mediator=False
		precision = 0
		file_name = ""
		operation_lin_log = 0
		ssum_version = 0
		reencryption_bytes = 0
		partition_type_h_v = 0
		mini_batch_size = 0



		for opt,arg in opts:

			if opt in ('-m', '--mediator'):
				mediator = True

			if opt in ('-n', '--host'):
				hname = arg

			if opt in ('-r', '--port'):
				port = arg

			if opt in ('-u', '--num-nodes'):
				num_nodes = int(arg)

			if opt in ('-d', '--num-dimensions'):
				number_of_dimensions = int(arg)

			if opt in ('-p', '--num-samples'):
				number_of_samples = int(arg)

			if opt in ('-s', '--num-shares'):
				number_of_data_segments = int(arg)

			if opt in ('-y', '--mediator-host'):
				mediator_node = arg

			if opt in ('-c', '--precision'):
				precision = int(arg)

			if opt in ('-f', '--file-name'):
				file_name = arg

			if opt in ('-o', '--operation-lin-log'):
				operation_lin_log = int(arg)

			if opt in ('-v', '--ssum-version'):
				ssum_version = int(arg)

			if opt in ('-b', '--reencryption-bytes'):
				reencryption_bytes = int(arg)

			if opt in ('-t', '--partition-type'):
				partition_type_h_v = int(arg)

			if opt in ('-i', '--batch-size'):
				mini_batch_size = int(arg)

			if opt in ('-h', '--help'):
				print_usage()
				sys.exit()


		if comm.debug_by_sm == True:
			print_parameters( mediator, hname, port, num_nodes, number_of_dimensions, number_of_samples, number_of_data_segments, mediator_node, precision, file_name, operation_lin_log, ssum_version, reencryption_bytes, partition_type_h_v)



		if mini_batch_size==number_of_samples:
			mini_batch = 0
		else:
			mini_batch = 1


		linear_cipher = True

		# Mediator functionalities
		if mediator is True:



			secsum_comm = comm_mediator_sec_sum.SecSumMediatorComm(hname, port, num_nodes)
			priv_task_mediator = privacy.SMC(10000, 100)

			if operation_lin_log==1:
				file_name = file_name + str(num_nodes) + "P_" + "DU_" + str(number_of_samples) + "samples_" + str(number_of_dimensions) + "dim_" +  str(precision) + "prec_" + str(reencryption_bytes) + "re_"  + str(mini_batch_size) + "batchsize" + ".csv"
			elif operation_lin_log==2:
				file_name = file_name + str(num_nodes) + "P_" + "log_DU_" + str(number_of_samples) + "samples_" + str(number_of_dimensions) + "dim_" +  str(precision) + "prec_" + str(reencryption_bytes) + "re_"  + str(mini_batch_size) + "batchsize" + ".csv"
			# result_file = open('/home/debian/smc/Results/' + file_name, 'w')
			# result_file.close()
			# result_file = open('/home/debian/smc/Results/' + file_name, 'a')

            # CODE FOR AWS
			result_file = open('/home/ubuntu/Results/' + file_name, 'w')
			result_file.close()
			result_file = open('/home/ubuntu/Results/' + file_name, 'a')



			#*************************************************************************************
			#Initial information (key, party IPs) exchange

			if comm.debug_by_sm == True:
				print '\nDEBUG: mediator now sending its public key'
			secsum_comm.send_mediator_public_key(priv_task_mediator.pub)


			if comm.debug_by_sm == True:
				print '\nDEBUG: mediator now receiving public keys'
			node_keys = secsum_comm.receive_public_keys()


			if comm.debug_by_sm == True:
				print '\nDEBUG: mediator now sending public keys'
			secsum_comm.send_public_keys(node_keys)


			if comm.debug_by_sm == True:
				print '\nDEBUG: node keys:\n'
				print node_keys


			parties = []

			for c in node_keys:
				parties.append(c)
			# if comm.debug_by_sm == True:
			# print '\nDEBUG: printing parties from keys:\n'
			# print parties

			# print '\nDEBUG: mediator now sending parties\' information to all nodes'
			secsum_comm.send_parties(parties)

			# *************************************************************************************












			#*************************************************************************************
			#Linear/Logistic Regression

			start_time = time.time()
			secsum_comm.comm.bytes_recv = 0
			secsum_comm.comm.bytes_sent = 0
			secsum_comm.comm.bytes_to_send = 0

			m = number_of_samples # number of samples
			n = number_of_dimensions # number of attributes



			if operation_lin_log==1 and partition_type_h_v==1:

				# alpha = .05 # used at HPE for synthetic data
                # ep = 0.1 # used at HPE for synthetic data
                # alpha = .00004 # bike_sharing
                # ep = 10 # bike_sharing
				alpha = .00000006 # year_prediction
				ep = 10 # year_prediction

				# print '\nx shapes: m=' + str(number_of_samples) + " n=" + str(number_of_dimensions)



				# initialize theta
				theta = np.random.random(n+1)
				# print 'theta: ' + str(theta)

				# print 'mediator now sending theta'
				secsum_comm.send_theta(theta)

				iterations = 1000
				error_per_iteration = [0] * (iterations+1)
				error_per_iteration[iterations] = 0
				converged = False


				while iterations>0 and not converged:


					if ssum_version == 1:

						if comm.debug_by_sm == True:
							print '\nDEBUG: mediator now receiving combined share ratios'
						combined_share_ratios_received = secsum_comm.receive_combined_share_ratios()


						# print 'combined_share_ratios_received information'
						# print len(combined_share_ratios_received)
						# for one_combined_share_ratios_received in combined_share_ratios_received:
						# 	print one_combined_share_ratios_received


						# print len(combined_share_ratios_received[parties[0]])
						# print len(combined_share_ratios_received[parties[0]][0])
						# print combined_share_ratios_received[parties[0]][0]

						combined_share_ratios_received_flat = []
						for c in combined_share_ratios_received:
							combined_share_ratios_received_flat_one_party = combined_share_ratios_received[c]
							combined_share_ratios_received_flat.append(combined_share_ratios_received_flat_one_party)

						# print 'combined_share_ratios_received_flat information'
						# print len(combined_share_ratios_received_flat)
						# print len(combined_share_ratios_received_flat[0])
						# print len(combined_share_ratios_received_flat[0][0])


						# if comm.debug_by_sm == True:
						# print '\nDEBUG: mediator now sending combined share ratios to the last party'
						secsum_comm.send_combined_share_ratios_to_last_party(combined_share_ratios_received_flat)



						# if comm.debug_by_sm == True:
						# print '\nDEBUG: mediator now receiving decrypted and shuffled data from all nodes'
						combined_share_ratios_decrypted_from_all_nodes = secsum_comm.receive_decrypted_n_shuffled_combined_share_ratios_from_first_party()

						# print 'combined_share_ratios_decrypted_from_all_nodes'
						# print len(combined_share_ratios_decrypted_from_all_nodes)
						# print len(combined_share_ratios_decrypted_from_all_nodes[0])
						# print len(combined_share_ratios_decrypted_from_all_nodes[0][0])
						# for one_combined_share_ratios_decrypted_from_all_nodes in combined_share_ratios_decrypted_from_all_nodes:
						# 	print one_combined_share_ratios_decrypted_from_all_nodes


						# print '\nDEBUG: mediator now computing sum'
						global_sum = priv_task_mediator.compute_sum_smc_v2(number_of_dimensions+2, number_of_data_segments, combined_share_ratios_decrypted_from_all_nodes, parties)

						# print '\n\n'
						# print global_sum



					elif ssum_version == 2:
						print 'not implemented yet, do not remove the commented code below'

						# if comm.debug_by_sm == True:
						# 	print '\nDEBUG: mediator now receiving encrypted data'
						# encrypted_data = secsum_comm.receive_encrypted_data()
						#
						# # print 'encrypted_data information'
						# # print len(encrypted_data)
						# # for one_encrypted_data in encrypted_data:
						# # 	print one_encrypted_data
						#
						# encrypted_data_flat = []
						#
						# for c in encrypted_data:
						# 	encrypted_data_flat_one_party = encrypted_data[c].split(',')
						# 	encrypted_data_flat.append(encrypted_data_flat_one_party)
						#
						#
						# if comm.debug_by_sm == True:
						# 	print '\nlen(encryped_data_flat): ' + str(len(encrypted_data_flat))
						# 	print 'len(encryped_data_flat[0]): ' + str(len(encrypted_data_flat[0]))
						# 	#print encryped_data_flat[0][0] prints the fisrt party's first shard
						#
						#
						# encrypted_data_parties_dimensions = long_matrix.matrix_zeros_3D(len(parties), number_of_dimensions+2, number_of_data_segments)
						# for i in range(len(parties)):
						# 	for j in range(number_of_dimensions+2):
						# 		data_per_party_dim = []
						# 		for k in range(number_of_data_segments):
						# 			data_per_party_dim.append(encrypted_data_flat[i][number_of_data_segments*j+k])
						# 		encrypted_data_parties_dimensions[i][j] = data_per_party_dim
						#
						#
						# # print '\nencrypted_data_party_dim'
						# # print encrypted_data_parties_dimensions
						#
						# # if comm.debug_by_sm == True:
						# print '\nDEBUG: mediator now sending encrypted data to appropriate nodes, ', time.time()
						# secsum_comm.send_combined_encrypted_data(encrypted_data_parties_dimensions, parties, number_of_dimensions+2)
						#
						#
						#
						# # if comm.debug_by_sm == True:
						# print '\nDEBUG: mediator now receiving decrypted and shuffled data from all nodes, ', time.time()
						# data_decrypted_from_all_nodes = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
						# print '\nDEBUG: mediator reeived decrypted and shuffled data from all nodes, ', time.time()
						#
						#
						# # if comm.debug_by_sm == True:
						# # 	print data_decrypted_from_all_nodes[parties[0]] # data from one party (entries = #of attributes handled * #of parties)
						# # 	print '\n'
						# # 	print data_decrypted_from_all_nodes[parties[0]][0] # one attribute, one party data
						# # 	print '\n'
						# # 	print data_decrypted_from_all_nodes[parties[0]][0][0] # one attribute, one party, one share data
						#
						# if comm.debug_by_sm == True:
						# 	print '\nDEBUG: mediator now computing sum'
						# global_sum = priv_task_mediator.compute_sum_smc_v1(number_of_dimensions+2, number_of_data_segments, data_decrypted_from_all_nodes, parties)
						# # global_sum = [0]*(number_of_dimensions+2)
						# # print '\n\nglobal sum'
						# print global_sum






					# print 'previous theta'
					# print theta
					for i in range(n+1):
						# print 'to be reduced: ' + str(float(alpha) * (float(1)/float(m)) * float(global_sum[i]))
						theta[i] -= float(alpha) * (float(1) / float(m)) * float(global_sum[i])
					# print 'new theta'
					# print theta

					error_per_iteration[iterations-1] = (float(1)/(float(2)*float(m))) * float(global_sum[n+1])

					E = error_per_iteration[iterations-1]
					J = error_per_iteration[iterations]

					if abs(J-E) <= ep:
						print 'Converged, iterations: ', 1000-iterations, '!!!'
						result_file.write('\n\n,Converged, Iterations: ' + str(1000-iterations) + ", E: " + str(E)+ '\n')
						converged = True
						break

					# print 'mediator now sending theta, ', time.time()
					secsum_comm.send_theta(theta)
					# print 'theta sent'



					print str(1000-iterations) + ',' +    str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)
					result_file.write(str(1000-iterations) + ',' +    str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send) + '\n')
					iterations-=1
					print 'theta: ' + str(theta)





				print 'theta: ' + str(theta)
				result_file.write(str(theta))




			elif operation_lin_log==2 and partition_type_h_v==1:

				# alpha = .5 #HPE
				# ep = .0001 #HPE

				# alpha = .05 #SUSY
				# ep = .005 #SUSY

				alpha = .005 #phishing
				ep = .005 #phishing

				# print '\nx shapes: m=' + str(number_of_samples) + " n=" + str(number_of_dimensions)



				# initialize theta
				# theta = np.random.random(n+1)
				#theta = [0.46279998, 0.95595229, 0.8444728, 0.72414489, 0.60901892, 0.29776349, 0.05276615, 0.11670447, 0.13615048, 0.56004463, 0.98853707] #HPE
				# theta = [ 0.9027307, 0.48326117,0.38885328,0.19880966,0.51637294,0.18247632,0.93120022,0.06705826,0.54439672,0.76566644,0.12083271,0.22752858,
                 #        0.2961895, 0.16700364,0.07147737,0.20457853,0.20927652,0.16728812,0.3657771 ] #SUSY
				theta = [ 0.68087846,0.18498136,0.58642008,0.31617384,0.33903203,0.03071062
                        ,0.38753119,0.74852595,0.73857484,0.19190034,0.02503086,0.78329695
                        ,0.46527149,0.92043165,0.91281168,0.51430939,0.32209679,0.13576409
                        ,0.19054007,0.82515688,0.01112064,0.0241652, 0.26500723,0.30349959
                        ,0.17098232,0.47292165,0.74528823,0.87754969,0.78089751,0.07684316
                        ,0.16870117] # phishing

				# print 'theta: ' + str(theta)

				# print 'mediator now sending theta'
				secsum_comm.send_theta(theta)
				iterations_total = 88
				iterations = iterations_total
				error_per_iteration = [0] * (iterations+1)
				error_per_iteration[iterations] = 0
				converged = False


				while iterations>0 and not converged:


					if ssum_version == 1:

						if comm.debug_by_sm == True:
							print '\nDEBUG: mediator now receiving combined share ratios'
						combined_share_ratios_received = secsum_comm.receive_combined_share_ratios()


						# print 'combined_share_ratios_received information'
						# print len(combined_share_ratios_received)
						# for one_combined_share_ratios_received in combined_share_ratios_received:
						# 	print one_combined_share_ratios_received


						# print len(combined_share_ratios_received[parties[0]])
						# print len(combined_share_ratios_received[parties[0]][0])
						# print combined_share_ratios_received[parties[0]][0]

						combined_share_ratios_received_flat = []
						for c in combined_share_ratios_received:
							combined_share_ratios_received_flat_one_party = combined_share_ratios_received[c]
							combined_share_ratios_received_flat.append(combined_share_ratios_received_flat_one_party)

						# print 'combined_share_ratios_received_flat information'
						# print len(combined_share_ratios_received_flat)
						# print len(combined_share_ratios_received_flat[0])
						# print len(combined_share_ratios_received_flat[0][0])


						# if comm.debug_by_sm == True:
						# print '\nDEBUG: mediator now sending combined share ratios to the last party'
						secsum_comm.send_combined_share_ratios_to_last_party(combined_share_ratios_received_flat)



						# if comm.debug_by_sm == True:
						# print '\nDEBUG: mediator now receiving decrypted and shuffled data from all nodes'
						combined_share_ratios_decrypted_from_all_nodes = secsum_comm.receive_decrypted_n_shuffled_combined_share_ratios_from_first_party()

						# print 'combined_share_ratios_decrypted_from_all_nodes'
						# print len(combined_share_ratios_decrypted_from_all_nodes)
						# print len(combined_share_ratios_decrypted_from_all_nodes[0])
						# print len(combined_share_ratios_decrypted_from_all_nodes[0][0])
						# for one_combined_share_ratios_decrypted_from_all_nodes in combined_share_ratios_decrypted_from_all_nodes:
						# 	print one_combined_share_ratios_decrypted_from_all_nodes


						# print '\nDEBUG: mediator now computing sum'
						global_sum = priv_task_mediator.compute_sum_smc_v2(number_of_dimensions+2, number_of_data_segments, combined_share_ratios_decrypted_from_all_nodes, parties)

						# print '\n\n'
						# print global_sum

					elif ssum_version == 2:
						print 'not implemented'

					# print 'previous theta'
					# print theta
					for i in range(n+1):
						# print 'to be reduced: ' + str(float(alpha) * (float(1)/float(m)) * float(global_sum[i]))
						theta[i] -= float(alpha) * (float(1) / float(m)) * float(global_sum[i])
					# print 'new theta'
					# print theta

					error_per_iteration[iterations-1] = -(float(1)/float(m)) * float(global_sum[n+1])

					E = error_per_iteration[iterations-1]
					J = error_per_iteration[iterations]

					if abs(J-E) <= ep  or E<0:
						print 'Converged, iterations: ', iterations_total-iterations, '!!!'
						converged = True

					# print 'mediator now sending theta, ', time.time()
					secsum_comm.send_theta(theta)
					# print 'theta sent'



					print str(iterations_total-iterations) + ',' +    str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent), E
					result_file.write(str(iterations_total-iterations) + ',' +    str(time.time()-start_time) + ',' + str(E) + '\n')
					iterations-=1





				print 'theta: ' + str(theta)
				result_file.write(str(theta))
				print 'iteration: ' + str(iterations_total-iterations)





			elif operation_lin_log==1 and partition_type_h_v==2:



				iterations = 1000


				while iterations>0:

					if ssum_version == 3:

						all_random_numbers = secsum_comm.receive_encrypted_random_numbers()

						# print 'all_random_numbers', len(all_random_numbers)
						# print all_random_numbers

						combined_encrypted_random_numbers = [None] * num_nodes *num_nodes * mini_batch_size

						combined_encrypted_random_numbers_index = 0
						for c in all_random_numbers:
							# print '\n'
							# print len(all_random_numbers[c]), len(all_random_numbers[c][0])
							for entries_for_one_party in all_random_numbers[c]:
								for one_entry in entries_for_one_party:
									combined_encrypted_random_numbers[combined_encrypted_random_numbers_index] = one_entry
									combined_encrypted_random_numbers_index +=1

						# print 'combined_encrypted_random_numbers'
						# print combined_encrypted_random_numbers
						#
						#
						# print '\nsending combined_encrypted_random_numbers'
						secsum_comm.send_combined_encrypted_random_numbers_to_all_parties(combined_encrypted_random_numbers, parties, mini_batch_size)

						global_sum = [0] * mini_batch_size
						anonymized_local_results = secsum_comm.receive_anonymized_local_results()

						for c in anonymized_local_results:
							# print 'len(anonymized_local_results[c])', len(anonymized_local_results[c])
							i = 0
							for val in anonymized_local_results[c]:
								global_sum[i] += float(val)
								i+=1

						# print 'sum values', global_sum



					elif ssum_version == 1:

						if comm.debug_by_sm == True:
							print '\nDEBUG: mediator now receiving combined share ratios'
						combined_share_ratios_received = secsum_comm.receive_combined_share_ratios()


						# print 'combined_share_ratios_received information'
						# print len(combined_share_ratios_received)
						# for one_combined_share_ratios_received in combined_share_ratios_received:
						# 	print one_combined_share_ratios_received


						# print len(combined_share_ratios_received[parties[0]])
						# print len(combined_share_ratios_received[parties[0]][0])
						# print combined_share_ratios_received[parties[0]][0]

						combined_share_ratios_received_flat = []
						for c in combined_share_ratios_received:
							combined_share_ratios_received_flat_one_party = combined_share_ratios_received[c]
							combined_share_ratios_received_flat.append(combined_share_ratios_received_flat_one_party)

						# print 'combined_share_ratios_received_flat information'
						# print len(combined_share_ratios_received_flat)
						# print len(combined_share_ratios_received_flat[0])
						# print len(combined_share_ratios_received_flat[0][0])


						# if comm.debug_by_sm == True:
						# print '\nDEBUG: mediator now sending combined share ratios to the last party'
						secsum_comm.send_combined_share_ratios_to_last_party(combined_share_ratios_received_flat)



						# if comm.debug_by_sm == True:
						# print '\nDEBUG: mediator now receiving decrypted and shuffled data from all nodes'
						combined_share_ratios_decrypted_from_all_nodes = secsum_comm.receive_decrypted_n_shuffled_combined_share_ratios_from_first_party()

						# print 'combined_share_ratios_decrypted_from_all_nodes'
						# print len(combined_share_ratios_decrypted_from_all_nodes)
						# print len(combined_share_ratios_decrypted_from_all_nodes[0])
						# print len(combined_share_ratios_decrypted_from_all_nodes[0][0])
						# for one_combined_share_ratios_decrypted_from_all_nodes in combined_share_ratios_decrypted_from_all_nodes:
						# 	print one_combined_share_ratios_decrypted_from_all_nodes


						# print '\nDEBUG: mediator now computing sum'
						global_sum = priv_task_mediator.compute_sum_smc_v2(mini_batch_size, number_of_data_segments, combined_share_ratios_decrypted_from_all_nodes, parties)

						# print '\n\n'


					elif ssum_version == 2:
						print 'not implemented'

					secsum_comm.send_global_sum(global_sum)

					# if iterations==90:
					# 	print global_sum


					print str(1000-iterations) + ',' +    str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)
					result_file.write(str(1000-iterations) + ',' +    str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send) + '\n')
					iterations-=1





			# print 'error cost'
			# print error_per_iteration



			end_time = time.time()
			bytes_transferred = secsum_comm.bytes_transferred()
			print 'Time elapsed: ' + str(end_time-start_time)
			print 'Bytes transferred: ' + str(bytes_transferred)
			print 'Bytes sent: ' + str(secsum_comm.comm.bytes_sent)
			result_file.close()

			# if comm.debug_by_sm == True:
			# 	print '**\n**\nmediator now terminating computation'
			# secsum_comm.terminate_computation()
            #
			# if comm.debug_by_sm == True:
			# 	print 'mediator now terminating communication'
            #
            #
			# secsum_comm.terminate_all()









		#Node functions
		else:

			secsum_comm = comm_node_sec_sum.SecSumNodeComm(hname, mediator_node, port, num_nodes)
			priv_task_node = privacy.SMC(10000, 100)




			#*************************************************************************************
			#Read Data
			# if operation_lin_log ==1:
			# 	data_file = open('/home/debian/smc/Data/' + file_name + ".csv", 'r')
			# elif operation_lin_log==2:
			# 	data_file = open('/home/debian/smc/Data/' + file_name + ".csv", 'r')

			data_file = open('/home/ubuntu/Data/' + file_name + ".csv", 'r')

			data_inputs = data_file.readlines()


			# if operation_lin_log==1:
			# 	file_name = file_name + str(num_nodes) + "P_" + "LinReg_DU_" + str(number_of_samples) + "samples_" + str(number_of_dimensions) + "dimen_" +  str(precision) + "prec_" + str(reencryption_bytes) + "onoion_bytes.csv"
			# elif operation_lin_log==2:
			# 	file_name = file_name + str(num_nodes) + "P_" + "LogReg_DU_" + str(number_of_samples) + "samples_" + str(number_of_dimensions) + "dimen_" +  str(precision) + "prec_" + str(reencryption_bytes) + "onoion_bytes.csv"
			# result_file = open('/home/debian/smc/Results/' + file_name, 'w')
			# result_file.close()
			# result_file = open('/home/debian/smc/Results/' + file_name, 'a')


			local_m = len(data_inputs)
			print 'local_m : ' + str(local_m)
			# print 'first input: ' + str(data_inputs[0])

			n = len(data_inputs[0].split(','))-1
			print 'count_column: ' + str(n+1)


			X = []
			y = []
			for data_input in data_inputs:

				data_row = data_input.split(',')
				for i in range(n+1):
					data_row[i] = float(data_row[i])

				if (len(data_row)!=number_of_dimensions+1):
					print 'error in data: dimension size in data file is different from command line input'
				X.append(data_row[:n])
				y.append(data_row[n])

			# print '\nX:'
			# for one_X in X:
			# 	print one_X
			# print '\ny:'
			# for one_y in y:
			# 	print one_y,
			#*************************************************************************************


			# print 'done0'


			#*************************************************************************************
			#Initial information (key, party IPs) exchange
			if comm.debug_by_sm == True:
				print '\nnode now receiving mediator public key'
			med_key = secsum_comm.receive_mediator_public_key()

			if comm.debug_by_sm == True:
				print med_key


			if comm.debug_by_sm == True:
				print '\nnode now setting mediator public key'
			priv_task_node.set_mediator_key(med_key)


			if comm.debug_by_sm == True:
				print '\nnode now sending public key'
			secsum_comm.send_public_key(priv_task_node.pub)


			if comm.debug_by_sm == True:
				print '\nnode now receiving public keys'
			keys = secsum_comm.receive_public_keys()

			if comm.debug_by_sm == True:
				print keys



			if comm.debug_by_sm == True:
				print '\nnode now setting nodes\' public keys'
			priv_task_node.set_nodes_public_keys(keys)


			# print 'done1'


			# print '\nnode now receiving all parties\' ip addresses'
			parties_ip = secsum_comm.receive_parties()


			if comm.debug_by_sm == True:
				print 'parties'
				print parties_ip

			parties = []
			parties_splitted = parties_ip.split('\'')

			if comm.debug_by_sm == True:
				print parties_splitted

			for i in range(len(parties_splitted)):
				if '.' in str(parties_splitted[i]):
					parties.append(str(parties_splitted[i]))

			# if comm.debug_by_sm == True:
			# print parties

			for i in range(len(parties)):
				if(parties[i]==hname):
					party_index_in_list = i
					break

			# if comm.debug_by_sm == True:
			# print 'party_index_in_list' + str(party_index_in_list)

			if party_index_in_list==0:
				next_party = parties[len(parties)-1]
			else:
				next_party = parties[party_index_in_list-1]

			# if comm.debug_by_sm == True:
			# print 'next_party' + next_party

			#*************************************************************************************









			#*************************************************************************************
			#Linear Regression

			start_time = time.time()
			secsum_comm.comm.bytes_recv = 0
			secsum_comm.comm.bytes_sent = 0



			if operation_lin_log==1 and partition_type_h_v == 1:

				# print 'node now receiving theta'
				theta_whole = secsum_comm.receive_theta()
				theta_whole = theta_whole[1:len(theta_whole)-1] # trim []
				theta = theta_whole.split()
				for i in range(len(theta)):
					theta[i] = float(theta[i])
				# print theta



				iterations = 10

				while True:

					J=0
					for i in range(local_m):
						h_theta = theta[0]
						for j in range(n):
							h_theta += X[i][j] * theta[j+1]
						J += (h_theta - y[i])**2


					gradients = [0] * ((n+1) + 1) # (n+1) for theta_0,...theta_n, 1 for J
					for i in range(local_m):
						h_theta = theta[0]
						for j in range(n):
							h_theta += X[i][j] * theta[j+1]
						gradients[0] += (h_theta - y[i])
					# gradients[0] = 1.0/m * gradients[0]

                    # FROM HPE
					for k in range(1, n+1):
						for i in range(local_m):
							h_theta = theta[0]
							for j in range(n):
								h_theta += X[i][j] * theta[j+1]
							gradients[k] += (h_theta - y[i])*X[i][k-1]


                    # # CHANGED TO FOLLOWING ##################################################
					# h_theta_array = [0]*local_m
					# for i in range(local_m):
					# 	h_theta_array[i] = theta[0]
					# 	for j in range(n):
					# 		h_theta_array[i] += X[i][j] * theta[j+1]
                    #
                    #
					# for k in range(1, n+1):
					# 	for i in range(local_m):
					# 		# h_theta = theta[0]
					# 		# for j in range(n):
					# 		# 	h_theta += X[i][j] * theta[j+1]
					# 		gradients[k] += (h_theta_array[i] - y[i])*X[i][k-1]
                    #
					# ###########################################################################



					gradients[len(gradients)-1] = J
					# print 'gradients: ', gradients




					if ssum_version == 1:

						# if comm.debug_by_sm == True:
						# print '\nnode now computing segmented data'
						segmented_data = priv_task_node.compute_data_segments(gradients, number_of_data_segments)


						# segmented data
						# [dim 1, share 1]   [dim 1, share 2]
						# [dim 2, share 1]   [dim 2, share 2]
						# [dim 3, share 1]   [dim 3, share 2]
						# [dim 4, share 1]   [dim 4, share 2]



						#aggregate data of the same share form different dimensions
						aggregated_data = []
						for i in range(number_of_data_segments):
							share_i_aggregated_data = 0
							for j in range(len(segmented_data)):
								share_i_aggregated_data += segmented_data[j][i]
							aggregated_data.append(round(share_i_aggregated_data, precision))

						# print '\naggregated_data'
						# print aggregated_data


						#compute ratio
						dimension_ratios_for_shares = [] # a 2d list, rows correspond to shares_i, columns correspond to ratio of dimensions
						for i in range(number_of_data_segments):
							dimension_ratios_for_one_share = []
							for j in range(len(segmented_data)):
								dimension_ratios_for_one_share.append(round(segmented_data[j][i]/aggregated_data[i], precision))
							dimension_ratios_for_shares.append(str(dimension_ratios_for_one_share))

						# for dimension_ratios_for_one_share in dimension_ratios_for_shares:
						# 	print dimension_ratios_for_one_share




						# encrypt aggregated data
						# if comm.debug_by_sm == True:
						# print '\nnode now encrypting aggregated data'
						if linear_cipher:
							encrypted_aggregated_data = priv_task_node.encrypt_aggregated_data_linear_cipher_growth(aggregated_data,reencryption_bytes)
						else:
							encrypted_aggregated_data = priv_task_node.encrypt_aggregated_data(aggregated_data)

						# print 'encrypted_aggregated_data'
						# for one_encrypted_aggregated_data in encrypted_aggregated_data:
						# 	print one_encrypted_aggregated_data

						# print 'len(encrypted_aggregated_data)'
						# print len(encrypted_aggregated_data)



						# encrypt ratios
						# if comm.debug_by_sm == True:
						# print '\nnode now encrypting dimension ratios'
						if linear_cipher:
							encrypted_ratios = priv_task_node.encrypt_ratios_linear_cipher_growth(dimension_ratios_for_shares, reencryption_bytes)
						else:
							encrypted_ratios = priv_task_node.encrypt_ratios(dimension_ratios_for_shares)

						# print 'encrypted_ratios'
						# for one_encrypted_ratio in encrypted_ratios:
						# 	print one_encrypted_ratio

						# print 'len(encrypted_ratios)'
						# print len(encrypted_ratios)


						# if comm.debug_by_sm == True:
						# print '\nnode now combining ratios with shares'
						combined_share_ratios = []
						for i in range(number_of_data_segments):
							one_combined_share_ratio = []
							one_combined_share_ratio.append(encrypted_aggregated_data[i])
							one_combined_share_ratio.append(encrypted_ratios[i])
							combined_share_ratios.append(one_combined_share_ratio)



						# if comm.debug_by_sm == True:
						# print '\nnode now sending combined share ratios to mediator'
						secsum_comm.send_combined_share_ratios(combined_share_ratios)




						if party_index_in_list==len(parties)-1: # if last party
							# print 'last party receiving combined share ratios from mediator'
							all_combined_share_ratios = secsum_comm.receive_combined_share_ratios_from_mediator()
							# print 'last party decrypt_n_shuffle combined share ratios'
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# print len(decrypted_n_shuffled_data)
							# print len(decrypted_n_shuffled_data[0])
							# print len(decrypted_n_shuffled_data[0][0])
							saved_q_hname = secsum_comm.comm.q_hname
							secsum_comm.comm.q_hname = next_party
							secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'last party sending decrypted_n_shuffled combined share ratios to next'
							# print decrypted_n_shuffled_data
							secsum_comm.send_decrypted_n_shuffled_data_to_node(decrypted_n_shuffled_data)
							secsum_comm.comm.q_hname = saved_q_hname
							secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							time.sleep(1*party_index_in_list)
						elif party_index_in_list==0:
							saved_q_hname = secsum_comm.comm.q_hname
							# secsum_comm.comm.q_hname = next_party
							# secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'first party receiving combined share ratios from previous'
							all_combined_share_ratios = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
							# print 'first party decrypt_n_shuffle combined share ratios'
							# print all_combined_share_ratios
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# secsum_comm.comm.q_hname = saved_q_hname
							# secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							# print 'first party sending decrypted_n_shuffled combined share ratios to mediator'
							secsum_comm.send_decrypted_n_shuffled_combined_share_ratios_to_mediator(decrypted_n_shuffled_data)
							# time.sleep(1)
						else:
							saved_q_hname = secsum_comm.comm.q_hname
							secsum_comm.comm.q_hname = next_party
							secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'mid party receiving combined share ratios from previous'
							all_combined_share_ratios = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
							# print 'mid party decrypt_n_shuffle combined share ratios'
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# print len(decrypted_n_shuffled_data)
							# print len(decrypted_n_shuffled_data[0])
							# print len(decrypted_n_shuffled_data[0][0])
							# print 'mid party sending decrypted_n_shuffled combined share ratios to next'
							secsum_comm.send_decrypted_n_shuffled_data_to_node(decrypted_n_shuffled_data)
							secsum_comm.comm.q_hname = saved_q_hname
							secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							time.sleep(1*party_index_in_list)


					# elif ssum_version == 2:
					#
					# 	if comm.debug_by_sm == True:
					# 		print '\nnode now computing segmented data'
					# 	segmented_data = priv_task_node.compute_data_segments(gradients, number_of_data_segments)
					#
					# 	# print 'segmented data'
					# 	# for one_segmented_data in segmented_data:
					# 	# 	print one_segmented_data
					#
					# 	# segmented data
					# 	# [dim 1, share 1]   [dim 1, share 2]
					# 	# [dim 2, share 1]   [dim 2, share 2]
					# 	# [dim 3, share 1]   [dim 3, share 2]
					# 	# [dim 4, share 1]   [dim 4, share 2]
					#
					#
					#
					# 	if comm.debug_by_sm == True:
					# 		print '\nsegmented data: '
					# 		for i in range(len(segmented_data)):
					# 			print segmented_data[i]
					#
					#
					# 	if comm.debug_by_sm == True:
					# 		print '\nnode now encrypting segmented data'
					# 	encrypted_segmented_data = priv_task_node.encrypt_data_segments(segmented_data)
					#
					#
					# 	if comm.debug_by_sm == True:
					# 		print '\nnode now sending segmented encrypted data'
					# 	secsum_comm.send_encrypted_data(encrypted_segmented_data)
					#
					#
					#
					#
					#
					# 	# if comm.debug_by_sm == True:
					# 	print '\nnode now receiving encrypted data, ', time.time()
					# 	data_to_decrypt_n_shuffle =  secsum_comm.receive_encrypted_data()
					#
					#
					# 	if comm.debug_by_sm == True:
					# 		print 'len(data_to_decrypt_n_shuffle)'  +str(len(data_to_decrypt_n_shuffle))
					# 		print 'len(data_to_decrypt_n_shuffle[0])' + str(len(data_to_decrypt_n_shuffle[0]))
					#
					# 	# TODO: need to write a loop according to (number of shares or number of attributes) and number of parties
					#
					# 	decrypted_n_shuffled_data =  priv_task_node.decrypt_n_shuffle(data_to_decrypt_n_shuffle, len(parties))
					# 	# print 'decrypted_n_shuffled_data'
					#
					# 	# for i in range(len(decrypted_n_shuffled_data)):
					# 	# 	for j in range(len(decrypted_n_shuffled_data[0])):
					# 	# 		print decrypted_n_shuffled_data[i][j]
					# 	# 		print '\n'
					#
					#
					#
					# 	saved_q_hname = secsum_comm.comm.q_hname
					# 	secsum_comm.comm.q_hname = next_party
					# 	secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
					#
					# 	for i in range(len(parties)-1):
					#
					# 		if party_index_in_list%2 == 0:
					# 			# print '\nnode now sending decrypted_n_shuffled_data'
					# 			secsum_comm.send_decrypted_n_shuffled_data_to_node(decrypted_n_shuffled_data)
					# 			# print '\nnode now receiving data_to_decrypt_n_shuffle'
					# 			data_to_decrypt_n_shuffle = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
					#
					# 		else:
					# 			# print '\nnode now receiving data_to_decrypt_n_shuffle'
					# 			data_to_decrypt_n_shuffle = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
					# 			# print '\nnode now sending decrypted_n_shuffled_data'
					# 			secsum_comm.send_decrypted_n_shuffled_data_to_node(decrypted_n_shuffled_data)
					#
					# 		if comm.debug_by_sm == True:
					# 			print '\nnode now decrypting and shuffling data'
					# 		decrypted_n_shuffled_data =  priv_task_node.decrypt_n_shuffle(data_to_decrypt_n_shuffle, len(parties))
					#
					# 		if comm.debug_by_sm == True:
					# 			print 'decrypted_n_shuffled_data'
					# 			# len(decrypted_n_shuffled_data) = number of attributes the node takes care of * number of parties
					# 			print 'len(decrypted_n_shuffled_data)' + str(len(decrypted_n_shuffled_data))
					# 			# len(decrypted_n_shuffled_data[0]) = number of segments
					# 			print 'len(decrypted_n_shuffled_data[0])' + str(len(decrypted_n_shuffled_data[0]))
					# 			for i in range(len(decrypted_n_shuffled_data)):
					# 				for j in range(len(decrypted_n_shuffled_data[0])):
					# 					print decrypted_n_shuffled_data[i][j]
					# 					print '\n'
					#
					#
					# 	secsum_comm.comm.q_hname = saved_q_hname
					# 	secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
					#
					#
					# 	theta_whole = secsum_comm.receive_theta()
					# 	theta_whole = secsum_comm.receive_theta()
					# 	print '\nsend_decrypted_n_shuffled_data_to_mediator, ', time.time()
					#
					# 	secsum_comm.send_decrypted_n_shuffled_data_to_mediator(decrypted_n_shuffled_data)
					# 	print '\nsent_decrypted_n_shuffled_data_to_mediator, ', time.time()
						# secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
						# print 'node now receiving theta from ' + secsum_comm.comm.q_hname
						# time.sleep(0.2)


					# time.sleep(10)
					# print 'receive_theta, ', time.time()
					theta_whole = secsum_comm.receive_theta()
					# print 'theta_received'
					theta_whole = theta_whole[1:len(theta_whole)-1] # trim []
					theta = theta_whole.split()
					for i in range(len(theta)):
						theta[i] = float(theta[i])
					# print theta

					# iterations-=1

					print ',' + str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)
					# result_file.write(str(1000-iterations) + ',' +    str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send) + '\n')




			elif operation_lin_log==2 and partition_type_h_v == 1:

				# print 'node now receiving theta'
				theta_whole = secsum_comm.receive_theta()
				theta_whole = theta_whole[1:len(theta_whole)-1] # trim []
				theta = theta_whole.split(', ')
				for i in range(len(theta)):
					theta[i] = float(theta[i])
				# print theta



				iterations = 10

				while True:

					J=0
					for i in range(local_m):
						z_in_h_theta = theta[0]
						for j in range(n):
							z_in_h_theta += X[i][j] * theta[j+1]
						h_theta = float(1) / (float(1) + math.exp(-z_in_h_theta))
						if h_theta>0 and 1-h_theta>0:
							J += y[i]*math.log(h_theta) + (1-y[i])*math.log(1-h_theta)


					gradients = [0] * ((n+1) + 1) # (n+1) for theta_0,...theta_n, 1 for J
					for i in range(local_m):
						z_in_h_theta = theta[0]
						for j in range(n):
							z_in_h_theta += X[i][j] * theta[j+1]
						h_theta = float(1) / (float(1) + math.exp(-z_in_h_theta))
						gradients[0] += (h_theta - y[i])
					# gradients[0] = 1.0/m * gradients[0]

					# print '\nnum_iterations: ' + str(num_iterations)

					for k in range(1, n+1):
						for i in range(local_m):
							z_in_h_theta = theta[0]
							for j in range(n):
								z_in_h_theta += X[i][j] * theta[j+1]
							h_theta = float(1) / (float(1) + math.exp(-z_in_h_theta))
							gradients[k] += (h_theta - y[i])*X[i][k-1]


					gradients[len(gradients)-1] = J
					# print 'gradients: ', gradients


					if ssum_version == 1:

						# if comm.debug_by_sm == True:
						# print '\nnode now computing segmented data'
						segmented_data = priv_task_node.compute_data_segments(gradients, number_of_data_segments)


						# segmented data
						# [dim 1, share 1]   [dim 1, share 2]
						# [dim 2, share 1]   [dim 2, share 2]
						# [dim 3, share 1]   [dim 3, share 2]
						# [dim 4, share 1]   [dim 4, share 2]



						#aggregate data of the same share form different dimensions
						aggregated_data = []
						for i in range(number_of_data_segments):
							share_i_aggregated_data = 0
							for j in range(len(segmented_data)):
								share_i_aggregated_data += segmented_data[j][i]
							aggregated_data.append(round(share_i_aggregated_data, precision))

						# print '\naggregated_data'
						# print aggregated_data


						#compute ratio
						dimension_ratios_for_shares = [] # a 2d list, rows correspond to shares_i, columns correspond to ratio of dimensions
						for i in range(number_of_data_segments):
							dimension_ratios_for_one_share = []
							for j in range(len(segmented_data)):
								dimension_ratios_for_one_share.append(round(segmented_data[j][i]/aggregated_data[i], precision))
							dimension_ratios_for_shares.append(str(dimension_ratios_for_one_share))

						# for dimension_ratios_for_one_share in dimension_ratios_for_shares:
						# 	print dimension_ratios_for_one_share




						# encrypt aggregated data
						# if comm.debug_by_sm == True:
						# print '\nnode now encrypting aggregated data'
						if linear_cipher:
							encrypted_aggregated_data = priv_task_node.encrypt_aggregated_data_linear_cipher_growth(aggregated_data,reencryption_bytes)
						else:
							encrypted_aggregated_data = priv_task_node.encrypt_aggregated_data(aggregated_data)

						# print 'encrypted_aggregated_data'
						# for one_encrypted_aggregated_data in encrypted_aggregated_data:
						# 	print one_encrypted_aggregated_data

						# print 'len(encrypted_aggregated_data)'
						# print len(encrypted_aggregated_data)



						# encrypt ratios
						# if comm.debug_by_sm == True:
						# print '\nnode now encrypting dimension ratios'
						if linear_cipher:
							encrypted_ratios = priv_task_node.encrypt_ratios_linear_cipher_growth(dimension_ratios_for_shares, reencryption_bytes)
						else:
							encrypted_ratios = priv_task_node.encrypt_ratios(dimension_ratios_for_shares)

						# print 'encrypted_ratios'
						# for one_encrypted_ratio in encrypted_ratios:
						# 	print one_encrypted_ratio

						# print 'len(encrypted_ratios)'
						# print len(encrypted_ratios)


						# if comm.debug_by_sm == True:
						# print '\nnode now combining ratios with shares'
						combined_share_ratios = []
						for i in range(number_of_data_segments):
							one_combined_share_ratio = []
							one_combined_share_ratio.append(encrypted_aggregated_data[i])
							one_combined_share_ratio.append(encrypted_ratios[i])
							combined_share_ratios.append(one_combined_share_ratio)



						# if comm.debug_by_sm == True:
						# print '\nnode now sending combined share ratios to mediator'
						secsum_comm.send_combined_share_ratios(combined_share_ratios)




						if party_index_in_list==len(parties)-1: # if last party
							# print 'last party receiving combined share ratios from mediator'
							all_combined_share_ratios = secsum_comm.receive_combined_share_ratios_from_mediator()
							# print 'last party decrypt_n_shuffle combined share ratios'
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# print len(decrypted_n_shuffled_data)
							# print len(decrypted_n_shuffled_data[0])
							# print len(decrypted_n_shuffled_data[0][0])
							saved_q_hname = secsum_comm.comm.q_hname
							secsum_comm.comm.q_hname = next_party
							secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'last party sending decrypted_n_shuffled combined share ratios to next'
							# print decrypted_n_shuffled_data
							secsum_comm.send_decrypted_n_shuffled_data_to_node(decrypted_n_shuffled_data)
							secsum_comm.comm.q_hname = saved_q_hname
							secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							time.sleep(1*party_index_in_list)
						elif party_index_in_list==0:
							saved_q_hname = secsum_comm.comm.q_hname
							# secsum_comm.comm.q_hname = next_party
							# secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'first party receiving combined share ratios from previous'
							all_combined_share_ratios = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
							# print 'first party decrypt_n_shuffle combined share ratios'
							# print all_combined_share_ratios
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# secsum_comm.comm.q_hname = saved_q_hname
							# secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							# print 'first party sending decrypted_n_shuffled combined share ratios to mediator'
							secsum_comm.send_decrypted_n_shuffled_combined_share_ratios_to_mediator(decrypted_n_shuffled_data)
							# time.sleep(1)
						else:
							saved_q_hname = secsum_comm.comm.q_hname
							secsum_comm.comm.q_hname = next_party
							secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'mid party receiving combined share ratios from previous'
							all_combined_share_ratios = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
							# print 'mid party decrypt_n_shuffle combined share ratios'
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# print len(decrypted_n_shuffled_data)
							# print len(decrypted_n_shuffled_data[0])
							# print len(decrypted_n_shuffled_data[0][0])
							# print 'mid party sending decrypted_n_shuffled combined share ratios to next'
							secsum_comm.send_decrypted_n_shuffled_data_to_node(decrypted_n_shuffled_data)
							secsum_comm.comm.q_hname = saved_q_hname
							secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							time.sleep(1*party_index_in_list)


						# secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
						# print 'node now receiving theta from ' + secsum_comm.comm.q_hname
						# time.sleep(0.2)



					elif ssum_version == 2:
						print 'not implemented'



					# time.sleep(10)
					# print 'receive_theta, ', time.time()
					theta_whole = secsum_comm.receive_theta()
					# print 'theta_received'
					theta_whole = theta_whole[1:len(theta_whole)-1] # trim []
					theta = theta_whole.split(', ')
					for i in range(len(theta)):
						theta[i] = float(theta[i])
					# print theta

					# iterations-=1

					print str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)


			elif operation_lin_log == 1 and partition_type_h_v ==2:



				# alpha = .00004 # bike sharing
				alpha = .00000006 # year prediction
				# alpha = .0001
				ep = 1

				if num_nodes == 2:
					if party_index_in_list==0:
						theta = np.random.random(n+1) # first party extimates theta_0
						theta = [0.54325137,  0.76674983,  0.93685311,  0.88211791,  0.84054159]
					else:
						theta = np.random.random(n)
						theta = [0.59784088,  0.11702678,  0.18340393,  0.48360023]


				elif num_nodes == 3:
					if party_index_in_list==0:
						# theta = np.random.random(n+1) # first party extimates theta_0
						# theta = [0.54325137,  0.76674983,  0.93685311,  0.88211791,  0.84054159] # bike sharing
						theta = [ 0.62890512,0.21008249,0.84289487,0.48136498,0.87971779,0.22769008 # year prediction
                                ,0.25166556,0.30342901,0.79796032,0.41635468,0.676529,0.23634854
                                ,0.63461594,0.99194021,0.64111492,0.02619329,0.1096782, 0.94323575
                                ,0.14943243,0.30496416,0.03124646,0.91368611,0.18529834,0.8557423
                                ,0.61656792,0.92395496,0.94905815,0.1080622, 0.96897292,0.56989753
                                ,0.53695216]
					elif party_index_in_list==1:
						# theta = np.random.random(n)
						# theta = [0.59784088,  0.11702678,  0.18340393,  0.48360023] # bike sharing
						theta = [0.03798241,0.03483172,0.91635817,0.23936035,0.32837788  # year prediction
                                ,0.68881081,0.91286351,0.08136249,0.71377351,0.04932085,0.39721575
                                ,0.45612695,0.91732499,0.65051071,0.69998359,0.78823552,0.54100402
                                ,0.85153391,0.49497598,0.01267469,0.38314258,0.78415682,0.77633527
                                ,0.67784089,0.13921523,0.34776344,0.18294795,0.98230885,0.58189116
                                ,0.64071796]
					else:
						# theta = np.random.random(n)
						# theta = [0.59784088,  0.11702678,  0.18340393,  0.48360023] # bike sharing
						theta = [0.21416678,0.36587488,0.14150635,0.92665741,0.06196585 # year prediction
                                ,0.80483901,0.43437648,0.45388927,0.26207349,0.667805,0.75714263
                                ,0.56266208,0.36783636,0.24536248,0.66330246,0.70875022,0.00737553
                                ,0.46145588,0.20028883,0.01297281,0.34813716,0.81350232,0.72395131
                                ,0.59120196,0.58664181,0.87979721,0.72955342,0.61670963,0.71663037
                                ,0.81793144]


				elif num_nodes == 4:
					if party_index_in_list==0:
						theta = [0.54325137,  0.76674983,  0.93685311]
					elif party_index_in_list==1:
						theta = [0.88211791,  0.84054159]
					elif party_index_in_list==2:
						theta = [0.59784088,  0.11702678]
					else:
						theta = [0.18340393,  0.48360023]

				elif num_nodes == 8:
					if party_index_in_list==0:
						theta = [0.54325137,  0.76674983]
					elif party_index_in_list==1:
						theta = [0.93685311]
					elif party_index_in_list==2:
						theta = [0.88211791]
					elif party_index_in_list==3:
						theta = [0.84054159]
					elif party_index_in_list==4:
						theta = [0.59784088]
					elif party_index_in_list==5:
						theta = [0.11702678]
					elif party_index_in_list==6:
						theta = [0.18340393]
					else:
						theta = [0.48360023]

				# print theta

				seeds = [103, 325, 388, 48, 939, 210, 217, 822, 632, 560, 494, 809,
						 545, 109, 347, 921, 77, 655, 34, 618, 196, 222, 139, 824,
						 659, 224, 71, 964, 10, 485, 391, 720, 438, 443, 478, 965,
						 203, 788, 48, 626, 324, 356, 631, 697, 29, 643, 121, 971,
						 461, 487, 14, 790, 65, 872, 662, 379, 373, 256, 461, 140,
						 74, 564, 421, 193, 349, 304, 371, 50, 536, 62, 290, 404,
						 40, 233, 151, 41, 474, 634, 770, 364, 3, 548, 177, 508,
						 427, 668, 880, 28, 216, 450, 674, 768, 28, 396, 269, 695,
						 239, 782, 976, 929, 378, 125, 350, 281, 664, 502, 626, 922,
						 328, 530, 254, 934, 711, 289, 708, 161, 81, 306, 580, 787,
						 839, 202, 393, 253, 126, 776, 441, 992, 492, 432, 614, 25,
						 701, 848, 582, 183, 345, 631, 666, 752, 318, 708, 747, 732,
						 328, 729, 615, 497, 864, 591, 763, 909, 848, 125, 444, 666,
						 678, 942, 280, 543, 791, 902, 782, 763, 515, 663, 455, 157,
						 694, 787, 687, 601, 786, 591, 708, 616, 271, 773, 296, 238,
						 266, 800, 649, 149, 313, 410, 297, 766, 230, 285, 738, 823,
						 402, 292, 15, 956, 115, 541, 12, 667, 960, 362, 26, 136, 462,
						 967, 775, 874, 750, 145, 265, 78, 136, 788, 312, 594, 420,
						 393, 553, 717, 628, 26, 208, 258, 276, 371, 674, 201, 404,
						 264, 567, 127, 846, 665, 775, 550, 109, 457, 927, 674, 587,
						 734, 954, 883, 609, 456, 4, 910, 794, 466]

				iterations = 1000

				while True:


					if mini_batch == 0:

						local_h_theta = [0] * (local_m)
						for i in range(local_m):
							if party_index_in_list==0:
								h_theta = theta[0]
							else:
								h_theta = 0
							for j in range(n):
								if party_index_in_list==0:
									h_theta += X[i][j] * theta[j+1]
								else:
									h_theta += X[i][j] * theta[j]
							local_h_theta[i] = h_theta

					elif mini_batch == 1:

						random.seed(seeds[(1000-iterations)%len(seeds)])
						samples_for_mini_batch = [random.randint(0,number_of_samples-1) for x in range(mini_batch_size)]

						local_h_theta = [0] * (mini_batch_size)
						for i in range(mini_batch_size):
							if party_index_in_list==0:
								h_theta = theta[0]
							else:
								h_theta = 0
							for j in range(n):
								if party_index_in_list==0:
									h_theta += X[samples_for_mini_batch[i]][j] * theta[j+1]
								else:
									h_theta += X[samples_for_mini_batch[i]][j] * theta[j]
							local_h_theta[i] = h_theta


					if ssum_version == 3:

						# print 'len(local_h_theta)', len(local_h_theta)

						random_nums = []
						for i in range(num_nodes):
							random_nums_one_party = []
							for j in range(len(local_h_theta)):
								random_nums_one_party.append(random.randint(1,100))
							random_nums.append(random_nums_one_party)

						# print random_nums

						encrypted_random_nums = priv_task_node.encrypt_random_numbers(random_nums)

						# print 'len(encrypted_random_nums), len(encrypted_random_nums[0])', len(encrypted_random_nums), len(encrypted_random_nums[0])

						# if hname == "172.31.25.45":
						# 	print encrypted_random_nums[0][0]
						# 	print elgamal.decrypt(priv_task_node.priv, encrypted_random_nums[0][0])




						secsum_comm.send_encrypted_random_numbers_to_mediator(encrypted_random_nums)


						received_combined_encrypted_random_numbers = secsum_comm.receive_combined_encrypted_random_numbers_from_mediator()

						# print 'received_combined_encrypted_random_numbers', len(received_combined_encrypted_random_numbers) # len = number_of_dimensions * number_of_parties
						# for received_combined_encrypted_random_number in received_combined_encrypted_random_numbers:
						# 	print received_combined_encrypted_random_number

						# combined_encrypted_random_numbers = re.split(', ', str(received_combined_encrypted_random_numbers)[1:len(received_combined_encrypted_random_numbers)-1])
						# print len(combined_encrypted_random_numbers), '\n'
						# for one_combined_encrypted_random_numbers in combined_encrypted_random_numbers:
						# 	print one_combined_encrypted_random_numbers

						combined_random_numbers = priv_task_node.decrypt_random_numbers(received_combined_encrypted_random_numbers)

						# for one_random_number in combined_random_numbers:
						# 	print one_random_number

						total_generated_numbers = []

						for i in range(len(local_h_theta)):
							total_generated_number = 0
							for j in range(num_nodes):
								total_generated_number+= random_nums[j][i]
							total_generated_numbers.append(total_generated_number)

						# print total_generated_numbers

						total_received_numbers = []
						for i in range(len(local_h_theta)):
							total_received_number = 0
							for j in range(num_nodes):
								total_received_number+= float(combined_random_numbers[i+j*len(local_h_theta)])
							total_received_numbers.append(total_received_number)

						# print 'total_generated', total_generated_numbers
						# print 'total_received', total_received_numbers


						send_to_mediator_final = [None]*len(local_h_theta)
						for i in range(len(local_h_theta)):
							send_to_mediator_final[i] = local_h_theta[i]+total_generated_numbers[i]-total_received_numbers[i]

						# print '\nsend_to_mediator_final', send_to_mediator_final



						secsum_comm.send_anonymized_local_results_to_mediator(send_to_mediator_final)






					elif ssum_version == 1:

						# if comm.debug_by_sm == True:
						# print '\nnode now computing segmented data'
						segmented_data = priv_task_node.compute_data_segments(local_h_theta, number_of_data_segments)


						# segmented data
						# [dim 1, share 1]   [dim 1, share 2]
						# [dim 2, share 1]   [dim 2, share 2]
						# [dim 3, share 1]   [dim 3, share 2]
						# [dim 4, share 1]   [dim 4, share 2]



						#aggregate data of the same share form different dimensions
						aggregated_data = []
						for i in range(number_of_data_segments):
							share_i_aggregated_data = 0
							for j in range(len(segmented_data)):
								share_i_aggregated_data += segmented_data[j][i]
							aggregated_data.append(round(share_i_aggregated_data, precision))

						# print '\naggregated_data'
						# print aggregated_data


						#compute ratio
						dimension_ratios_for_shares = [] # a 2d list, rows correspond to shares_i, columns correspond to ratio of dimensions
						for i in range(number_of_data_segments):
							dimension_ratios_for_one_share = []
							for j in range(len(segmented_data)):
								dimension_ratios_for_one_share.append(round(segmented_data[j][i]/aggregated_data[i], precision))
							dimension_ratios_for_shares.append(str(dimension_ratios_for_one_share))

						# for dimension_ratios_for_one_share in dimension_ratios_for_shares:
						# 	print dimension_ratios_for_one_share




						# encrypt aggregated data
						# if comm.debug_by_sm == True:
						# print '\nnode now encrypting aggregated data'
						if linear_cipher:
							encrypted_aggregated_data = priv_task_node.encrypt_aggregated_data_linear_cipher_growth(aggregated_data,reencryption_bytes)
						else:
							encrypted_aggregated_data = priv_task_node.encrypt_aggregated_data(aggregated_data)

						# print 'encrypted_aggregated_data'
						# for one_encrypted_aggregated_data in encrypted_aggregated_data:
						# 	print one_encrypted_aggregated_data

						# print 'len(encrypted_aggregated_data)'
						# print len(encrypted_aggregated_data)



						# encrypt ratios
						# if comm.debug_by_sm == True:
						# print '\nnode now encrypting dimension ratios'
						if linear_cipher:
							encrypted_ratios = priv_task_node.encrypt_ratios_linear_cipher_growth(dimension_ratios_for_shares, reencryption_bytes)
						else:
							encrypted_ratios = priv_task_node.encrypt_ratios(dimension_ratios_for_shares)

						# print 'encrypted_ratios'
						# for one_encrypted_ratio in encrypted_ratios:
						# 	print one_encrypted_ratio

						# print 'len(encrypted_ratios)'
						# print len(encrypted_ratios)


						# if comm.debug_by_sm == True:
						# print '\nnode now combining ratios with shares'
						combined_share_ratios = []
						for i in range(number_of_data_segments):
							one_combined_share_ratio = []
							one_combined_share_ratio.append(encrypted_aggregated_data[i])
							one_combined_share_ratio.append(encrypted_ratios[i])
							combined_share_ratios.append(one_combined_share_ratio)



						# if comm.debug_by_sm == True:
						# print '\nnode now sending combined share ratios to mediator'
						secsum_comm.send_combined_share_ratios(combined_share_ratios)




						if party_index_in_list==len(parties)-1: # if last party
							# print 'last party receiving combined share ratios from mediator'
							all_combined_share_ratios = secsum_comm.receive_combined_share_ratios_from_mediator()
							# print 'last party decrypt_n_shuffle combined share ratios'
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# print len(decrypted_n_shuffled_data)
							# print len(decrypted_n_shuffled_data[0])
							# print len(decrypted_n_shuffled_data[0][0])
							saved_q_hname = secsum_comm.comm.q_hname
							secsum_comm.comm.q_hname = next_party
							secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'last party sending decrypted_n_shuffled combined share ratios to next'
							# print decrypted_n_shuffled_data
							secsum_comm.send_decrypted_n_shuffled_data_to_node(decrypted_n_shuffled_data)
							secsum_comm.comm.q_hname = saved_q_hname
							secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							time.sleep(1*party_index_in_list)
						elif party_index_in_list==0:
							saved_q_hname = secsum_comm.comm.q_hname
							# secsum_comm.comm.q_hname = next_party
							# secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'first party receiving combined share ratios from previous'
							all_combined_share_ratios = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
							# print 'first party decrypt_n_shuffle combined share ratios'
							# print all_combined_share_ratios
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# secsum_comm.comm.q_hname = saved_q_hname
							# secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							# print 'first party sending decrypted_n_shuffled combined share ratios to mediator'
							secsum_comm.send_decrypted_n_shuffled_combined_share_ratios_to_mediator(decrypted_n_shuffled_data)
							# time.sleep(1)
						else:
							saved_q_hname = secsum_comm.comm.q_hname
							secsum_comm.comm.q_hname = next_party
							secsum_comm.comm.sock_req.connect("tcp://" + next_party + ":" + secsum_comm.comm.port)
							# print 'mid party receiving combined share ratios from previous'
							all_combined_share_ratios = secsum_comm.receive_decrypted_n_shuffled_data_from_node()
							# print 'mid party decrypt_n_shuffle combined share ratios'
							if linear_cipher:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios_linear_cipher_growth(all_combined_share_ratios, num_nodes)
							else:
								decrypted_n_shuffled_data = priv_task_node.decrypt_n_shuffle_combined_share_ratios(all_combined_share_ratios, num_nodes)
							# print 'decrypted_n_shuffled_data information'
							# print decrypted_n_shuffled_data
							# print len(decrypted_n_shuffled_data)
							# print len(decrypted_n_shuffled_data[0])
							# print len(decrypted_n_shuffled_data[0][0])
							# print 'mid party sending decrypted_n_shuffled combined share ratios to next'
							secsum_comm.send_decrypted_n_shuffled_data_to_node(decrypted_n_shuffled_data)
							secsum_comm.comm.q_hname = saved_q_hname
							secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
							time.sleep(1*party_index_in_list)


						# secsum_comm.comm.sock_req.connect("tcp://" + secsum_comm.comm.q_hname + ":" + secsum_comm.comm.port)
						# print 'node now receiving theta from ' + secsum_comm.comm.q_hname
						# time.sleep(0.2)

					elif ssum_version == 2:
						print 'not implemented'








					# time.sleep(10)
					# print 'node now receiving global sum'
					global_sum_whole = secsum_comm.receive_global_sum()
					# print 'theta_received'
					global_sum_whole = global_sum_whole[1:len(global_sum_whole)-1] # trim []
					global_sum = global_sum_whole.split(', ')
					for i in range(len(global_sum)):
						global_sum[i] = float(global_sum[i])

					# print global_sum


					if party_index_in_list==0:
						gradients = [0] * (n+1)
					else:
						gradients = [0] * n


					if mini_batch == 0:

						if party_index_in_list==0:

							for i in range(local_m):
								gradients[0] += (global_sum[i] - y[i])


							for k in range(1, n+1):
								for i in range(local_m):
									gradients[k] += (global_sum[i] - y[i])*X[i][k-1]

						else:

							for k in range(n):
								for i in range(local_m):
									gradients[k] += (global_sum[i] - y[i])*X[i][k]



						if party_index_in_list==0:

							for i in range(n+1):
								theta[i] -= float(alpha) * (float(1) / float(local_m)) * float(gradients[i])

						else:

							for i in range(n):
								theta[i] -= float(alpha) * (float(1) / float(local_m)) * float(gradients[i])


					elif mini_batch == 1:

						if party_index_in_list==0:

							for i in range(mini_batch_size):
								gradients[0] += (global_sum[i] - y[samples_for_mini_batch[i]])


							for k in range(1, n+1):
								for i in range(mini_batch_size):
									gradients[k] += (global_sum[i] - y[samples_for_mini_batch[i]])*X[samples_for_mini_batch[i]][k-1]

						else:

							for k in range(n):
								for i in range(mini_batch_size):
									gradients[k] += (global_sum[i] - y[samples_for_mini_batch[i]])*X[samples_for_mini_batch[i]][k]



						if party_index_in_list==0:

							for i in range(n+1):
								theta[i] -= float(alpha) * (float(1) / float(mini_batch_size)) * float(gradients[i])

						else:

							for i in range(n):
								theta[i] -= float(alpha) * (float(1) / float(mini_batch_size)) * float(gradients[i])

					# print 'theta', theta


					print str(1000-iterations) + ',' + str(time.time()-start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)

					if 1000-iterations==100: # or (1000-iterations==88 and party_index_in_list==0):
						print theta
						break

					iterations-=1





			end_time = time.time()
			bytes_transferred = secsum_comm.bytes_transferred()
			print 'Time elapsed: ' + str(end_time-start_time)
			print 'Bytes transferred: ' + str(bytes_transferred)
			print 'Bytes sent: ' + str(secsum_comm.comm.bytes_sent)
			data_file.close()
			# result_file.close()

			# if comm.debug_by_sm == True:
			# 	print '**\n**\nnode now terminating computation'
			# secsum_comm.terminate_computation()
            #
			# if comm.debug_by_sm == True:
			# 	print 'node now terminating communication'
			# secsum_comm.terminate_all()

	except Usage, err:
		print >> sys.stderr, err.msg
		print >> sys.stderr, "for help use --help"

if __name__ == "__main__":
	sys.exit(main())