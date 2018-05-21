import zmq
import csv
import json
import numpy
import base64
import sys
import random
import time
import comm
import comm_mediator
import long_matrix

class SecSumMediatorComm(object):
    """
        Implements secure-sum-protocol communication for the mediator.
    """



    def __init__(self, _hname, _port, _num):
        """
            Creates a generic mediator communication object.
        """
        self.comm = comm_mediator.MediatorComm(_hname, _port, _num)




    def send_mediator_public_key(self, med_key):
        """
            Mediator sends public key to all nodes.
        """
        if comm.cryptosystem == 0:
            #############################################
            # ELGAMAL CRYPTOSYSTEM
            self.comm.reply_all(comm.MSG_KEY_MEDIATOR_NODE,
                              str(med_key.p) + '|' + str(med_key.g) + '|' + str(med_key.h) + '|' + str(med_key.iNumBits))
            #############################################

        elif comm.cryptosystem == 1:
            #############################################
            # PAILLIER CRYPTOSYSTEM
            self.comm.reply_all(comm.MSG_KEY_MEDIATOR_NODE, str(med_key.n))
            #############################################




    def receive_public_keys(self):
        """
            Mediator receives public keys from all nodes.
        """
        content = self.comm.reply_all(comm.MSG_KEY_NODE_MEDIATOR, "")
        return content




    def send_public_keys(self, node_keys):
        """
            Mediator sends the public key list to all nodes.
        """
        content = ','.join(node_keys.values())
        self.comm.reply_all(comm.MSG_KEYS_MEDIATOR_NODE, content)




    def receive_encrypted_data(self):
        """
            Mediator receives encrypted data from all nodes.
        """
        content = self.comm.reply_all(comm.MSG_EDATA_NODE_MEDIATOR, "")
        return content



    def receive_combined_share_ratios(self):
        """
            Mediator receives combined_share_ratios from all nodes.
        """
        content = self.comm.reply_all(comm.MSG_CSRDATA_NODE_MEDIATOR, "")
        return content



    def send_parties(self, parties):
        """
            Mediator now sending parties' ip addresses to all nodes
        """
        self.comm.reply_all(comm.MSG_PARTIES_MEDIATOR_NODE, str(parties))


    def send_combined_share_ratios_to_last_party(self, combined_share_ratios_received):

        self.comm.reply_to_one(comm.MSG_CSRDATA_MEDIATOR_LNODE, combined_share_ratios_received)


    def receive_decrypted_n_shuffled_combined_share_ratios_from_first_party(self):

        content = self.comm.reply_to_one(comm.MSG_DSDATA_FNODE_MEDIATOR, "")
        return content



    def send_combined_encrypted_data(self, encrypted_data_parties_dimensions, parties, number_of_dimensions):
        """
            Mediator sends encrypted data to nodes appropriately.
        """

        # encrypted_data_parties_dimensions[party_no][dimension_no]

        # Build the content
        # If there are 5 dimensions (attributes) in the data, and there are three parties, the encryption order is folowing:
        # Dim 0: M, P0, P1, P2
        # Dim 1: M, P1, P2, P0
        # Dim 2: M, P2, P0, P1
        # Dim 3: M, P0, P1, P2
        # Dim 4: M, P1, P2, P0
        # The decryption order needs to be reversed. Therefore, e.g., P2 receives dim 0 and dim 3.

        content = {}

        for party_i in range(len(parties)):
            j = 0
            encrypted_data_party_i = []
            # build the content for party_i
            # for P2, the dimensions it has to receive are 0 and 3
            # (2+1)%3 + 0*3 = 0
            # (2+1)%3 + 1*3 = 3
            # (2+1)%3 + 2*3 = 6 (more than the number of actual dimensions)
            # .....stop
            while ((party_i+1)%len(parties)) + j*len(parties) < number_of_dimensions:
                # print (party_i+1)%len(parties) + j*len(parties),
                # print encrypted_data_parties_dimensions[0][(party_i+1)%len(parties) + j*len(parties)]

                # we now have the dimension to send to party party_i
                # get that dimension from each party
                for k in range(len(parties)):
                    encrypted_data_party_i.append(encrypted_data_parties_dimensions[k][(party_i+1)%len(parties) + j*len(parties)])
                # print encrypted_data_parties_dimensions[:,(party_i + 1) % len(parties) + j * len(parties)]
                # encrypted_data_party.append(encrypted_data_parties_dimensions[:,(party_i+1)%len(parties)*j].tolist())

                j+=1

            content[parties[party_i]] = encrypted_data_party_i
            # print encrypted_data_party_i
            # print '\n'

        # Send the content
        self.comm.reply(comm.MSG_EDATA_MEDIATOR_NODE, content)

        # print 'send_combined_encrypted_data: contents'
        # for c in content:
        #     print content[c]




    def receive_decrypted_n_shuffled_data_from_node(self):
        """
            Mediator receives decrypted and shuffled data.
        """
        content = self.comm.reply_all(comm.MSG_DSTATA_NODE_MEDIATOR, "")
        return content




    def terminate_computation(self):
        """
            Mediator terminates computation.
        """
        self.comm.terminate_computation()




    def terminate_all(self):
        """
            Mediator terminates communication.
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

    def send_theta(self, theta):
        """
            Mediator sends public key to all nodes.
        """
        self.comm.reply_all(comm.MSG_THETA_MEDIATOR_NODE, str(theta))




    def receive_gradients_n_cost(self):

        content = self.comm.reply_all(comm.MSG_GRADIENT_COST_NODE_MEDIATOR, "")
        return content

    def receive_raw_data_X(self):

        content = self.comm.reply_all(comm.MSG_RAWDATAX_NODE_MEDIATOR, "")
        return content

    def receive_raw_data_y(self):

        content = self.comm.reply_all(comm.MSG_RAWDATAY_NODE_MEDIATOR, "")
        return content





    def receive_local_h_theta(self):

        content = self.comm.reply_all(comm.MSG_LOCAL_H_THETA_NODE_MEDIATOR, "")
        return content

    def send_global_sum(self, global_sum):
        """
            Mediator sends public key to all nodes.
        """
        self.comm.reply_all(comm.MSG_GLOBALSUM_MEDIATOR_NODE, str(global_sum))