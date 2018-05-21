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



		# Mediator functionalities
		if mediator is True:



			secsum_comm = comm_mediator_sec_sum.SecSumMediatorComm(hname, port, num_nodes)
			priv_task_mediator = privacy.SMC(10000, 100)


			if operation_lin_log==1:
				file_name = file_name + str(num_nodes) + "P_" + "DT_" + str(number_of_samples) + "samples_" + str(number_of_dimensions) + "dim_" +  str(precision) + "prec_" + str(reencryption_bytes) + "re_"  + str(mini_batch_size) + "batchsize" + ".csv"
			elif operation_lin_log==2:
				file_name = file_name + str(num_nodes) + "P_" + "log_DT_" + str(number_of_samples) + "samples_" + str(number_of_dimensions) + "dim_" +  str(precision) + "prec_" + str(reencryption_bytes) + "re_"  + str(mini_batch_size) + "batchsize" + ".csv"

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
			master_start_time = time.time()
			total_comp_time = 0
			total_comm_time = 0
			secsum_comm.comm.bytes_recv = 0
			secsum_comm.comm.bytes_sent = 0



			m = number_of_samples # number of samples
			n = number_of_dimensions # number of attributes



			if operation_lin_log==1 and partition_type_h_v ==1:

				iterations = 1000
				error_per_iteration = [0] * (iterations+1)
				error_per_iteration[iterations] = 0
				converged = False
				# alpha = .05 # used at HPE for synthetic data
                # ep = 0.1 # used at HPE for synthetic data
                # alpha = .00004 # bike_sharing
                # ep = 10 # bike_sharing
				alpha = .00000006 # year_prediction
				ep = 10 # year_prediction

				# print '\nx shapes: m=' + str(number_of_samples) + " n=" + str(number_of_dimensions)


				start_time = time.time()
				# initialize theta
				theta = np.random.random(n+1)
				print 'theta: ' + str(theta)
				end_time = time.time()
				total_comp_time+= end_time-start_time




				while iterations>0 and not converged:

					# Disributed Trusted
					start_time = time.time()
					secsum_comm.send_theta(theta)
					gradients_n_cost_all_nodes = secsum_comm.receive_gradients_n_cost()
					end_time = time.time()
					total_comm_time+= end_time-start_time







					start_time = time.time()

					# print '\n'
					gradients_n_cost_all_nodes_per_node_row = []
					for c in gradients_n_cost_all_nodes:
						one_party_gradients_n_cost_all_nodes = gradients_n_cost_all_nodes[c]
						# print one_party_gradients_n_cost_all_nodes
						# one_party_gradients_n_cost_all_nodes = one_party_gradients_n_cost_all_nodes[1: len(one_party_gradients_n_cost_all_nodes)-1]
						# print one_party_gradients_n_cost_all_nodes
						# one_party_gradients_n_cost_all_nodes = one_party_gradients_n_cost_all_nodes.split(', ')
						# print one_party_gradients_n_cost_all_nodes
						gradients_n_cost_all_nodes_per_node_row.append(one_party_gradients_n_cost_all_nodes)

					# print '\n\ngradients_n_cost_all_nodes_per_node_row'
					# print gradients_n_cost_all_nodes_per_node_row


					# print '\n'
					global_sum = [0] * (n+2)
					for i in range(n+2):
						for j in range(len(gradients_n_cost_all_nodes_per_node_row)):
							# print gradients_n_cost_all_nodes_per_node_row[j][i]
							global_sum[i] += gradients_n_cost_all_nodes_per_node_row[j][i]

					# print '\nglobal_sum'
					# print global_sum



					# print 'previous theta'
					# print theta
					for i in range(n+1):
						# print 'to be reduced: ' + str(float(alpha) * (float(1)/float(m)) * float(global_sum[i]))
						theta[i] = theta[i] - float(alpha) * (float(1)/float(m)) * float(global_sum[i])
					# print 'new theta'
					# print theta

					error_per_iteration[iterations-1] = (float(1)/(float(2)*float(m))) * float(global_sum[n+1])

					E = error_per_iteration[iterations-1]
					J = error_per_iteration[iterations]

					if abs(J-E) <= ep:
						print 'Converged, iterations: ', 1000-iterations , '!!!'
						converged = True

					end_time = time.time()
					total_comp_time+= end_time-start_time




					print str(1000-iterations) + ',' +  str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent)
					iterations-=1
					print 'THETA: ' + str(theta)



				print 'Iterations: ' + str(1000-iterations)
				print 'THETA: ' + str(theta)



			elif operation_lin_log==2 and partition_type_h_v==1:

				iterations_total = 88
				iterations = iterations_total
				error_per_iteration = [0] * (iterations+1)
				error_per_iteration[iterations] = 0
				converged = False
				# alpha = .5 #HPE
				# ep = .0001

				# alpha = .05 #SUSY
				# ep = .005 #SUSY

				alpha = .005 #phishing
				ep = .005 #phishing

				# print '\nx shapes: m=' + str(number_of_samples) + " n=" + str(number_of_dimensions)


				start_time = time.time()
				# initialize theta
				# theta = np.random.random(n+1)
				#theta_whole = "[0.46279998 0.95595229 0.8444728 0.72414489 0.60901892 0.29776349 0.05276615 0.11670447 0.13615048 0.56004463 0.98853707]"
				#theta = [0.46279998, 0.95595229, 0.8444728, 0.72414489, 0.60901892, 0.29776349, 0.05276615, 0.11670447, 0.13615048, 0.56004463, 0.98853707]
				# theta = [ 0.9027307, 0.48326117,0.38885328,0.19880966,0.51637294,0.18247632,0.93120022,0.06705826,0.54439672,0.76566644,0.12083271,0.22752858
                 #            ,0.2961895, 0.16700364,0.07147737,0.20457853,0.20927652,0.16728812,0.3657771 ] #SUSY
				theta = [ 0.68087846,0.18498136,0.58642008,0.31617384,0.33903203,0.03071062
                        ,0.38753119,0.74852595,0.73857484,0.19190034,0.02503086,0.78329695
                        ,0.46527149,0.92043165,0.91281168,0.51430939,0.32209679,0.13576409
                        ,0.19054007,0.82515688,0.01112064,0.0241652, 0.26500723,0.30349959
                        ,0.17098232,0.47292165,0.74528823,0.87754969,0.78089751,0.07684316
                        ,0.16870117] # phishing
				# print 'theta: ' + str(theta)
				end_time = time.time()
				total_comp_time+= end_time-start_time

				# theta_whole = theta_whole[1:len(theta_whole)-1] # trim []
				# theta = theta_whole.split()
				# # print theta
				# for i in range(len(theta)):
				# 	theta[i] = float(theta[i])




				while iterations>0 and not converged:

					# Disributed Trusted
					start_time = time.time()
					# if iterations==300:
					# 	secsum_comm.send_theta(theta_whole)
					# else:
					secsum_comm.send_theta(theta)
					gradients_n_cost_all_nodes = secsum_comm.receive_gradients_n_cost()
					end_time = time.time()
					total_comm_time+= end_time-start_time







					start_time = time.time()

					# print '\n'
					gradients_n_cost_all_nodes_per_node_row = []
					for c in gradients_n_cost_all_nodes:
						one_party_gradients_n_cost_all_nodes = gradients_n_cost_all_nodes[c]
						# print one_party_gradients_n_cost_all_nodes
						# one_party_gradients_n_cost_all_nodes = one_party_gradients_n_cost_all_nodes[1: len(one_party_gradients_n_cost_all_nodes)-1]
						# print one_party_gradients_n_cost_all_nodes
						# one_party_gradients_n_cost_all_nodes = one_party_gradients_n_cost_all_nodes.split(', ')
						# print one_party_gradients_n_cost_all_nodes
						gradients_n_cost_all_nodes_per_node_row.append(one_party_gradients_n_cost_all_nodes)

					# print '\n\ngradients_n_cost_all_nodes_per_node_row'
					# print gradients_n_cost_all_nodes_per_node_row


					# print '\n'
					global_sum = [0] * (n+2)
					for i in range(n+2):
						for j in range(len(gradients_n_cost_all_nodes_per_node_row)):
							# print gradients_n_cost_all_nodes_per_node_row[j][i]
							global_sum[i] += gradients_n_cost_all_nodes_per_node_row[j][i]

					# print '\nglobal_sum'
					# print global_sum



					# print 'previous theta'
					# print theta
					for i in range(n+1):
						# print 'to be reduced: ' + str(float(alpha) * (float(1)/float(m)) * float(global_sum[i]))
						theta[i] = theta[i] - float(alpha) * (float(1)/float(m)) * float(global_sum[i])
					# print 'new theta'
					# print theta

					error_per_iteration[iterations-1] = -(float(1)/float(m)) * float(global_sum[n+1])

					E = error_per_iteration[iterations-1]
					J = error_per_iteration[iterations]

					if abs(J-E) <= ep  or E<0:
						print 'Converged, iterations: ', iterations_total-iterations , '!!!'
						converged = True

					end_time = time.time()
					total_comp_time+= end_time-start_time




					print str(iterations_total-iterations) + ',' +  str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent), E
					result_file.write(str(iterations_total-iterations) + ',' +    str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send) + '\n')
					iterations-=1



				print 'Iterations: ' + str(iterations_total-iterations)
				print 'THETA: ' + str(theta)
				result_file.write(str(theta))





			elif operation_lin_log==1 and partition_type_h_v==2:



				iterations = 1000


				while iterations>0:


					combined_local_h_theta = secsum_comm.receive_local_h_theta()


					combined_local_h_theta_flat = []
					for c in combined_local_h_theta:
						combined_local_h_theta_flat_one_party = combined_local_h_theta[c]
						combined_local_h_theta_flat.append(combined_local_h_theta_flat_one_party)


					# print 'combined_local_h_theta_flat dimensions'
					# print len(combined_local_h_theta_flat), len(combined_local_h_theta_flat[0])
					# print combined_local_h_theta_flat




					global_sum = [0] * mini_batch_size
					for i in range(mini_batch_size):
						for j in range(len(parties)):
							global_sum[i] += float(combined_local_h_theta_flat[j][i])



					secsum_comm.send_global_sum(global_sum)


					# if iterations==90:
					# 	print global_sum


					print str(1000-iterations) + ',' +    str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)
					result_file.write(str(1000-iterations) + ',' +    str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send) + '\n')
					iterations-=1




			# print 'error cost'
			# print error_per_iteration


			master_end_time = time.time()
			bytes_transferred = secsum_comm.bytes_transferred()
			print '\nTime elapsed: ' + str(master_end_time-master_start_time)
			print 'Communication time: ' + str(total_comm_time)
			print 'Computation time: ' + str(total_comp_time)
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
			master_start_time = time.time()

			total_comp_time = 0
			total_comm_time = 0
			gradient_comp_time = 0
			error_comp_time = 0
			secsum_comm.comm.bytes_recv = 0
			secsum_comm.comm.bytes_sent = 0



			if operation_lin_log==1 and partition_type_h_v==1:

				while True:
					total_comm_start_time = time.time()
					# print 'node now receiving theta'
					theta_whole = secsum_comm.receive_theta()
					total_comm_end_time = time.time()
					total_comm_time+= total_comm_end_time-total_comm_start_time



					total_comp_start_time = time.time()

					theta_whole = theta_whole[1:len(theta_whole)-1] # trim []
					theta = theta_whole.split()
					# print theta
					for i in range(len(theta)):
						theta[i] = float(theta[i])


					# compute gradients
					gradient_comp_start_time = time.time()

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



					gradient_comp_end_time = time.time()
					gradient_comp_time += gradient_comp_end_time-gradient_comp_start_time



					# compute error
					error_comp_start_time = time.time()
					J=0
					for i in range(local_m):
						h_theta = theta[0]
						for j in range(n):  # computes h_theta(x)
							h_theta += X[i][j] * theta[j+1]
						J += (h_theta - y[i])**2
					error_comp_end_time = time.time()
					error_comp_time += error_comp_end_time-error_comp_start_time


					gradients[len(gradients)-1] = J

					# print 'gradients_n_cost'
					# print gradients



					total_comp_end_time = time.time()
					total_comp_time+= total_comp_end_time-total_comp_start_time





					total_comm_start_time = time.time()

					# Distributed Trusted
					secsum_comm.send_gradients_n_cost(gradients)

					total_comm_end_time = time.time()
					total_comm_time+= total_comm_end_time-total_comm_start_time


					master_end_time = time.time()
					# bytes_transferred = secsum_comm.bytes_transferred()
					# print '\nTime elapsed: ' + str(master_end_time-master_start_time)
					# print 'Communication time: ' + str(total_comm_time)
					# print 'Computation time: ' + str(total_comp_time)
					# print 'Bytes transferred: ' + str(bytes_transferred)
					# print 'Bytes sent: ' + str(secsum_comm.comm.bytes_sent)
					# print 'Gradient Computation time: ' + str(gradient_comp_time)
					# print 'Error Computation time: ' + str(error_comp_time)

					print str(master_end_time-master_start_time) +','+ str(secsum_comm.comm.bytes_sent)


			elif operation_lin_log==2 and partition_type_h_v==1:

				while True:
					total_comm_start_time = time.time()
					# print 'node now receiving theta'
					theta_whole = secsum_comm.receive_theta()
					total_comm_end_time = time.time()
					total_comm_time+= total_comm_end_time-total_comm_start_time



					total_comp_start_time = time.time()

					theta_whole = theta_whole[1:len(theta_whole)-1] # trim []
					theta = theta_whole.split(', ')
					# print theta
					for i in range(len(theta)):
						theta[i] = float(theta[i])


					# compute gradients
					gradient_comp_start_time = time.time()

					gradients = [0] * ((n+1) + 1) # (n+1) for theta_0,...theta_n, 1 for J
					for i in range(local_m):
						z_in_h_theta = theta[0]
						for j in range(n):
							z_in_h_theta += X[i][j] * theta[j+1]
						h_theta = float(1) / (float(1) + math.exp(-z_in_h_theta))
						gradients[0] += (h_theta - y[i])
					# gradients[0] = 1.0/m * gradients[0]


					for k in range(1, n+1):
						for i in range(local_m):
							z_in_h_theta = theta[0]
							for j in range(n):
								z_in_h_theta += X[i][j] * theta[j+1]
							h_theta = float(1) / (float(1) + math.exp(-z_in_h_theta))
							gradients[k] += (h_theta - y[i])*X[i][k-1]

					gradient_comp_end_time = time.time()
					gradient_comp_time += gradient_comp_end_time-gradient_comp_start_time



					# compute error
					error_comp_start_time = time.time()
					J=0
					for i in range(local_m):
						z_in_h_theta = theta[0]
						for j in range(n):
							z_in_h_theta += X[i][j] * theta[j+1]
						h_theta = float(1) / (float(1) + math.exp(-z_in_h_theta))
						if h_theta>0 and 1-h_theta>0:
							J += y[i]*math.log(h_theta) + (1-y[i])*math.log(1-h_theta)
					error_comp_end_time = time.time()
					error_comp_time += error_comp_end_time-error_comp_start_time


					gradients[len(gradients)-1] = J

					# print 'gradients_n_cost'
					# print gradients



					total_comp_end_time = time.time()
					total_comp_time+= total_comp_end_time-total_comp_start_time





					total_comm_start_time = time.time()

					# Distributed Trusted
					secsum_comm.send_gradients_n_cost(gradients)

					total_comm_end_time = time.time()
					total_comm_time+= total_comm_end_time-total_comm_start_time



					master_end_time = time.time()
					# bytes_transferred = secsum_comm.bytes_transferred()
					# print '\nTime elapsed: ' + str(master_end_time-master_start_time)
					# print 'Communication time: ' + str(total_comm_time)
					# print 'Computation time: ' + str(total_comp_time)
					# print 'Bytes transferred: ' + str(bytes_transferred)
					# print 'Bytes sent: ' + str(secsum_comm.comm.bytes_sent)
					# print 'Gradient Computation time: ' + str(gradient_comp_time)
					# print 'Error Computation time: ' + str(error_comp_time)

					print str(master_end_time-master_start_time) +','+ str(secsum_comm.comm.bytes_sent)




			elif operation_lin_log==1 and partition_type_h_v==2:

				# alpha = .00004 # bike sharing
				# alpha = .00000006 # year prediction
				alpha = .0001
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
						theta = np.random.random(n+1) # first party extimates theta_0
						theta = [0.54325137,  0.76674983,  0.93685311,  0.88211791,  0.84054159] # bike sharing
						# theta = [ 0.62890512,0.21008249,0.84289487,0.48136498,0.87971779,0.22769008 # year prediction
                         #        ,0.25166556,0.30342901,0.79796032,0.41635468,0.676529,0.23634854
                         #        ,0.63461594,0.99194021,0.64111492,0.02619329,0.1096782, 0.94323575
                         #        ,0.14943243,0.30496416,0.03124646,0.91368611,0.18529834,0.8557423
                         #        ,0.61656792,0.92395496,0.94905815,0.1080622, 0.96897292,0.56989753
                         #        ,0.53695216]
					elif party_index_in_list==1:
						theta = np.random.random(n)
						theta = [0.59784088,  0.11702678,  0.18340393,  0.48360023] # bike sharing
						# theta = [0.03798241,0.03483172,0.91635817,0.23936035,0.32837788  # year prediction
                         #        ,0.68881081,0.91286351,0.08136249,0.71377351,0.04932085,0.39721575
                         #        ,0.45612695,0.91732499,0.65051071,0.69998359,0.78823552,0.54100402
                         #        ,0.85153391,0.49497598,0.01267469,0.38314258,0.78415682,0.77633527
                         #        ,0.67784089,0.13921523,0.34776344,0.18294795,0.98230885,0.58189116
                         #        ,0.64071796]
					else:
						theta = np.random.random(n)
						theta = [0.59784088,  0.11702678,  0.18340393,  0.48360023] # bike sharing
						# theta = [0.21416678,0.36587488,0.14150635,0.92665741,0.06196585 # year prediction
                         #        ,0.80483901,0.43437648,0.45388927,0.26207349,0.667805,0.75714263
                         #        ,0.56266208,0.36783636,0.24536248,0.66330246,0.70875022,0.00737553
                         #        ,0.46145588,0.20028883,0.01297281,0.34813716,0.81350232,0.72395131
                         #        ,0.59120196,0.58664181,0.87979721,0.72955342,0.61670963,0.71663037
                         #        ,0.81793144]

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

				# seeds = [random.randint(1,1000) for x in range(250)]
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



				if mini_batch == 0:

					while True:

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


						secsum_comm.send_local_h_theta(local_h_theta)
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

						# print 'theta', theta


						print str(1000-iterations) + ',' + str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)

						if 1000-iterations==89:
							print theta
							break

						iterations-=1



				elif mini_batch == 1:

					while True:

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




						secsum_comm.send_local_h_theta(local_h_theta)
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


						print str(1000-iterations) + ',' + str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)

						if 1000-iterations==89:
							print theta
							break

						iterations-=1


			elif operation_lin_log==2 and partition_type_h_v==2: # needs works

				alpha = .5
				ep = .0001

				if num_nodes == 2:
					if party_index_in_list==0:
						theta = np.random.random(n+1) # first party extimates theta_0
						theta = [0.54325137,  0.76674983,  0.93685311,  0.88211791,  0.84054159]
					else:
						theta = np.random.random(n)
						theta = [0.59784088,  0.11702678,  0.18340393,  0.48360023]

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

				# seeds = [random.randint(1,1000) for x in range(250)]
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

				iterations_total = 58
				iterations = iterations_total



				if mini_batch == 0:

					while True:

						local_h_theta = [0] * (local_m)
						for i in range(local_m):
							if party_index_in_list==0:
								z_in_h_theta  = theta[0]
							else:
								z_in_h_theta  = 0
							for j in range(n):
								if party_index_in_list==0:
									z_in_h_theta += X[i][j] * theta[j+1]
								else:
									z_in_h_theta += X[i][j] * theta[j]
							local_z_in_h_theta[i] = z_in_h_theta


						secsum_comm.send_local_h_theta(local_h_theta)
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

						# print 'theta', theta


						print str(iterations_total-iterations) + ',' + str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)

						if iterations_total-iterations==89:
							print theta
							break

						iterations-=1



				elif mini_batch == 1:

					while True:

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




						secsum_comm.send_local_h_theta(local_h_theta)
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


						print str(iterations_total-iterations) + ',' + str(time.time()-master_start_time) + ',' + str(secsum_comm.comm.bytes_sent) + ',' + str(secsum_comm.comm.bytes_to_send)

						# if iterations_total-iterations==89:
						# 	print theta
						# 	break

						iterations-=1




			# end_time = time.time()
			bytes_transferred = secsum_comm.bytes_transferred()
			# print 'Time elapsed: ' + str(end_time-start_time)
			print 'Bytes transferred: ' + str(bytes_transferred)
			print 'Bytes sent: ' + str(secsum_comm.comm.bytes_sent)

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