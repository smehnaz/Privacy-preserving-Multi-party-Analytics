import zmq
import csv
import json
import numpy
import base64
import sys
import random
import time
import comm
import comm_node
import long_matrix

class SecSumNodeComm(object):
    """
        Implements secure-sum-protocol communication for a data-node.
    """



    def __init__(self, _hname, _q_hname, _port, _num_nodes):
        """
            Creates a generic node communication object.
        """
        self.comm = comm_node.NodeComm(_hname, _q_hname, _port, _num_nodes)




    def receive_mediator_public_key(self):
        """
            Node receives the mediator's public key.
        """
        content = self.comm.request(comm.MSG_KEY_MEDIATOR_NODE, "")

        return content




    def send_public_key(self, key):
        """
            Node sends its public key to the mediator.
        """
        if comm.debug_by_sm == True:
            print 'DEBUG: send_public_key: node sending public key, call request'
        # content = str(key)

        if comm.cryptosystem == 0:
            #############################################
            # ELGAMAL CRYPTOSYSTEM
            self.comm.request(comm.MSG_KEY_NODE_MEDIATOR,
                              str(key.p) + '|' + str(key.g) + '|' + str(key.h) + '|' + str(key.iNumBits))
            #############################################

        elif comm.cryptosystem == 1:
            #############################################
            # PAILLIER CRYPTOSYSTEM
            self.comm.request(comm.MSG_KEY_NODE_MEDIATOR, str(key.n))
            #############################################




    def receive_public_keys(self):
        """
            Node receives the list of public keys.
        """
        content = self.comm.request(comm.MSG_KEYS_MEDIATOR_NODE, "")
        # Shagufta: rsplit splits from right
        node_keys = content.rsplit(',')

        # for c in range(len(node_keys)):
        # 	node_keys[c] = long(node_keys[c])

        return node_keys




    def send_encrypted_data(self, encrypted_segmented_data):
        """
            Node sends its encrypted segments to the mediator.
        """
        content = comm.pack_2D_matrix_smc(encrypted_segmented_data)
        self.comm.request(comm.MSG_EDATA_NODE_MEDIATOR, content)


    def send_combined_share_ratios(self, combined_share_ratios):
        """
            Node sends decrypted and shuffled data to next node for further decryption and shuffling.
        """
        self.comm.request(comm.MSG_CSRDATA_NODE_MEDIATOR, combined_share_ratios)


    def receive_parties(self):
        """
            Node receives all parties' ip addresses.
        """
        content = self.comm.request(comm.MSG_PARTIES_MEDIATOR_NODE, "")
        return content


    def receive_combined_share_ratios_from_mediator(self):
        """
            Node receives all parties' combined_share_ratios_from_nediator.
        """
        content = self.comm.request(comm.MSG_CSRDATA_MEDIATOR_LNODE, "")
        return content


    def receive_encrypted_data(self):
        """
            Node receives data to decrypt and shuffle.
        """
        content = self.comm.request(comm.MSG_EDATA_MEDIATOR_NODE, "")
        return content




    def send_decrypted_n_shuffled_data_to_node(self, decrypted_n_shuffled_data):
        """
            Node sends decrypted and shuffled data to next node for further decryption and shuffling.
        """
        self.comm.request(comm.MSG_DSTATA_NODE_NODE, decrypted_n_shuffled_data)




    def receive_decrypted_n_shuffled_data_from_node(self):
        """
            Node receives decrypted and shuffled data from previous node for further decryption and shuffling.
        """
        content = self.comm.reply(comm.MSG_DSTATA_NODE_NODE, "")
        return  content




    def send_decrypted_n_shuffled_data_to_mediator(self, decrypted_n_shuffled_data):
        """
            Node sends decrypted and shuffled data to the mediator.
        """
        self.comm.request(comm.MSG_DSTATA_NODE_MEDIATOR, decrypted_n_shuffled_data)


    def send_decrypted_n_shuffled_combined_share_ratios_to_mediator(self, decrypted_n_shuffled_data):
        """
            Node sends decrypted and shuffled data to the mediator.
        """
        # print 'send_decrypted_n_shuffled_combined_share_ratios_to_mediator, type :' + comm.MSG_DSDATA_FNODE_MEDIATOR
        self.comm.request(comm.MSG_DSDATA_FNODE_MEDIATOR, decrypted_n_shuffled_data)




    def terminate_computation(self):
        """
            Node terminates computation.
        """
        self.comm.terminate_computation()




    def terminate_all(self):
        """
            Node terminates communication.
        """
        self.comm.terminate_all()




    def bytes_transferred(self):
        """
            Compute the bytes transferred.
        """
        return self.comm.bytes_sent + self.comm.bytes_recv














    ###########################################################################################
    #### LINEAR REGRESSION
    ###########################################################################################

    def receive_theta(self):
        """
            Node receives the mediator's public key.
        """
        content = self.comm.request(comm.MSG_THETA_MEDIATOR_NODE, "")

        return content

    def send_gradients_n_cost(self, gradients_n_cost):
        """
            Node sends decrypted and shuffled data to the mediator.
        """
        self.comm.request(comm.MSG_GRADIENT_COST_NODE_MEDIATOR, gradients_n_cost)


    def send_raw_data_X(self, raw_data):
        """
            Node sends decrypted and shuffled data to the mediator.
        """
        self.comm.request(comm.MSG_RAWDATAX_NODE_MEDIATOR, raw_data)

    def send_raw_data_y(self, raw_data):
        """
            Node sends decrypted and shuffled data to the mediator.
        """
        self.comm.request(comm.MSG_RAWDATAY_NODE_MEDIATOR, raw_data)






    def receive_global_sum(self):
        """
            Node receives the mediator's public key.
        """
        content = self.comm.request(comm.MSG_GLOBALSUM_MEDIATOR_NODE, "")

        return content

    def send_local_h_theta(self, local_h_theta):
        """
            Node receives the mediator's public key.
        """
        self.comm.request(comm.MSG_LOCAL_H_THETA_NODE_MEDIATOR, local_h_theta)