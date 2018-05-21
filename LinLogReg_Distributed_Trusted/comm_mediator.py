import zmq
import csv
import json
import numpy
import base64
import sys
import random
import time
import comm

class MediatorComm(object):
    """
        Generic mediator communication class.
    """

    def __init__(self, _hname, _port, _num):
        """
        """
        self.hname = _hname
        self.port = _port

        # Shagufta: zmq setups
        self.context = zmq.Context()
        self.sock_rep = self.context.socket(zmq.REP)
        self.sock_rep.bind("tcp://*:" + self.port)

        self.num_parties = _num
        # self.comp = _comp

        self.bytes_sent = 0
        self.bytes_to_send = 0
        self.bytes_recv = 0




    def reply_all(self, _type, content):
        """
            Server side of a client-server interaction where all clients get the same response.
        """
        n = 0

        # received is an array, for each source there is a content, received[jsn['src']] = jsn['content']

        # if comm.debug_by_sm == True:
        # if _type == "14":
        # print 'reply_all: type: ' + _type

        # print 'reply_all: content: ' + content

        received = {}

        while n < self.num_parties:
            msg_recv = ""
            msg_send = ""

            try:
                # if comm.debug_by_sm == True:
                # if _type == "14":
                #     print "reply_all: waiting for message reply all"

                msg_recv = self.sock_rep.recv()

                # if comm.debug_by_sm == True:
                # if _type == "14":
                #     print "reply_all: message received"

                jsn = json.loads(msg_recv)

                # logging
                self.bytes_recv = self.bytes_recv + sys.getsizeof(msg_recv)

                if jsn['type'] == _type and jsn['src'] not in received:
                    # if comm.debug_by_sm == True:
                    # if _type == "14":
                    # print 'reply_all: new_message', msg_recv
                    received[jsn['src']] = jsn['content']
                    n = n + 1

                    msg_id = str(random.randint(0, 1000))
                    msg_send = comm.pack_msg(_type, msg_id, content, self.hname, jsn['src'])

                    self.sock_rep.send(msg_send)

                    # logging
                    self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)
                    self.bytes_to_send = self.bytes_to_send + sys.getsizeof(msg_send)
                else:
                    # if comm.debug_by_sm == True:
                    # if _type == "14":
                    #     print 'reply_all: old_message'
                    # print 'reply_all: type_mismatched, wait: expected = ' + _type + ", received = " + jsn['type']
                    msg_id = str(random.randint(0, 1000))
                    # Shagufta: now, it sends MSG_FAILURE and with empty content ""
                    msg_send = comm.pack_msg(comm.MSG_FAILURE, msg_id, "", self.hname, jsn['src'])
                    self.sock_rep.send(msg_send)
                    self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)

            except:
                print >> sys.stderr, "Communication error."
                print >> sys.stderr, "Message sent: ", msg_send
                print >> sys.stderr, "Message received: ", msg_recv

                raise

        return received




    def reply(self, _type, content):
        """
            Server side of a client-server interaction where each client gets a specific response.
        """
        n = 0
        received = {}

        while n < self.num_parties:
            msg_recv = ""
            msg_send = ""

            try:
                if comm.debug_by_sm == True:
                    print "waiting for message reply, ", _type

                msg_recv = self.sock_rep.recv()

                if comm.debug_by_sm == True:
                    print "message received"

                jsn = json.loads(msg_recv)

                # logging
                self.bytes_recv = self.bytes_recv + sys.getsizeof(msg_recv)

                if jsn['type'] == _type and jsn['src'] not in received:
                    received[jsn['src']] = jsn['content']
                    n = n + 1

                    msg_id = str(random.randint(0, 1000))

                    # Shagufta: different form reply_all here: content vs content[jsn['src']]
                    msg_send = comm.pack_msg(_type, msg_id, content[jsn['src']], self.hname, jsn['src'])

                    self.sock_rep.send(msg_send)

                    # logging
                    self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)
                    self.bytes_to_send = self.bytes_to_send + sys.getsizeof(msg_send)
                else:
                    msg_id = str(random.randint(0, 1000))
                    msg_send = comm.pack_msg(comm.MSG_FAILURE, msg_id, "", self.hname, jsn['src'])
                    self.sock_rep.send(msg_send)
                    self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)

            except:
                print >> sys.stderr, "Communication error."
                print >> sys.stderr, "Message sent: ", msg_send
                print >> sys.stderr, "Message received: ", msg_recv

                raise

        return received



    def reply_to_one(self, _type, content):
        """
            Server side of a client-server interaction where only one client gets response.
        """
        n = 0
        msg_received = ""

        msg_recv = ""
        msg_send = ""

        while(1):
            try:
                # if comm.debug_by_sm == True:
                # print "reply_to_one waiting for message reply"

                msg_recv = self.sock_rep.recv()

                # if comm.debug_by_sm == True:
                # print "reply_to_one message received"

                jsn = json.loads(msg_recv)

                # logging
                self.bytes_recv = self.bytes_recv + sys.getsizeof(msg_recv)

                # print "TYPES: " + jsn['type'] + " vs " + _type

                if jsn['type'] == _type:
                    msg_received = jsn['content']
                    # print "reply_to_one message received " + msg_recv
                    msg_id = str(random.randint(0, 1000))

                    # Shagufta: different form reply_all here: content vs content[jsn['src']]
                    msg_send = comm.pack_msg(_type, msg_id, content, self.hname, jsn['src'])
                    # print "reply_to_one if" + msg_send
                    self.sock_rep.send(msg_send)

                    # logging
                    self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)
                    self.bytes_to_send = self.bytes_to_send + sys.getsizeof(msg_send)
                    break
                else:
                    # print "reply_to_one message received nothing"
                    # print 'reply_all: type_mismatched, wait: expected = ' + _type + ", received = " + jsn['type']
                    msg_id = str(random.randint(0, 1000))
                    msg_send = comm.pack_msg(comm.MSG_FAILURE, msg_id, "", self.hname, jsn['src'])
                    # print "reply_to_one else" + msg_send
                    self.sock_rep.send(msg_send)
                    self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)

            except:
                print >> sys.stderr, "Communication error."
                print >> sys.stderr, "Message sent: ", msg_send
                print >> sys.stderr, "Message received: ", msg_recv

                raise

        return msg_received



    def terminate_computation(self):
        """
            Mediator terminates computation.
        """
        self.reply_all(comm.MSG_TERM_COMP, "")



    def terminate_all(self):
        """
            Mediator terminates communication.
        """
        self.reply_all(comm.MSG_TERM_ALL, "")