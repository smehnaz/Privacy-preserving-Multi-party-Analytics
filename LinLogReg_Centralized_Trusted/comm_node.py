import zmq
import csv
import json
import numpy
import base64
import sys
import random
import time
import comm

class NodeComm(object):
    """
        Generic node communication class.
    """

    def __init__(self, _hname, _q_hname, _port, _num_nodes):
        """
        """
        self.hname = _hname
        self.q_hname = _q_hname
        self.port = _port

        # Shagufta: zmq setups
        self.context = zmq.Context()

        self.sock_rep = self.context.socket(zmq.REP)
        self.sock_rep.bind("tcp://*:" + self.port)

        self.sock_req = self.context.socket(zmq.REQ)
        self.sock_req.connect("tcp://" + self.q_hname + ":" + self.port)

        self.num_nodes = _num_nodes
        self.comp = 0
        self.bytes_sent = 0
        self.bytes_to_send = 0
        self.bytes_recv = 0
        self.wait = 1




    def request(self, _type, content):
        """
            Client side of a client-server interaction.
        """
        msg_id = str(random.randint(0, 1000))

        # if _type == "14":
        #     print 'request: type: ' + _type # + ' content: ' + str(content)


        while True:
            msg_send = ""
            msg_recv = ""

            try:
                if comm.debug_by_sm == True:
                    print "request: Sending message"

                msg_send = comm.pack_msg(_type, msg_id, content, self.hname, self.q_hname)
                self.sock_req.send(msg_send)

                # if _type == "14":
                #     print msg_send

                # if comm.debug_by_sm == True:
                # if _type == "14":
                # print "request: Message sent, type: ", _type

                # logging
                self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)

                # if comm.debug_by_sm == True:
                # if _type == "14":
                # print "request: Waiting for message"

                msg_recv = self.sock_req.recv()

                # if comm.debug_by_sm == True:
                # if _type == "14":
                #     print "request: Message received"

                jsn = json.loads(msg_recv)

                # logging
                self.bytes_recv = self.bytes_recv + sys.getsizeof(msg_recv)

                if jsn['type'] == _type:
                    # if comm.debug_by_sm == True:
                    # print 'request: type matched: ' + comm.MSG_LIST[int(_type)]
                    self.bytes_to_send = self.bytes_to_send + sys.getsizeof(msg_send)
                    content = jsn['content']
                    self.wait = 1
                    break
                else:
                    # if comm.debug_by_sm == True:
                    # print 'request: type_mismatched, wait: expected = ' + _type + ", received = " + jsn['type'] + " wait: " +  str(self.wait)
                    time.sleep(self.wait)
                    self.wait = 2 * self.wait

            except:
                print >> sys.stderr, "Communication error."
                print >> sys.stderr, "Message sent: ", msg_send
                print >> sys.stderr, "Message received: ", msg_recv

                raise

        return content




    def reply(self, _type, content):
        """
            Server side of a client-server interaction where each client gets a specific response.
        """
        n = 0
        received = 0

        # if comm.debug_by_sm == True:
        # print 'reply: type: ' + _type

        msg_recv = ""
        msg_send = ""

        while True:
            try:
                # if comm.debug_by_sm == True:
                # print "reply:waiting for message reply"

                msg_recv = self.sock_rep.recv()

                # if comm.debug_by_sm == True:
                # print "reply:message received"

                jsn = json.loads(msg_recv)

                # logging
                self.bytes_recv = self.bytes_recv + sys.getsizeof(msg_recv)

                if jsn['type'] == _type:
                    received = jsn['content']
                    n = n + 1

                    msg_id = str(random.randint(0, 1000))

                    # Shagufta: different form reply_all here: content vs content[jsn['src']]
                    msg_send = comm.pack_msg(_type, msg_id, "", self.hname, jsn['src'])

                    # print msg_send
                    # print 'reply: type_matched'
                    self.sock_rep.send(msg_send)

                    # logging
                    self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)
                    self.bytes_to_send = self.bytes_to_send + sys.getsizeof(msg_send)
                    break

                else:
                    msg_id = str(random.randint(0, 1000))
                    # print 'reply: type_mismatched, wait: expected = ' + _type + ", received = " + jsn['type']
                    msg_send = comm.pack_msg(comm.MSG_FAILURE, msg_id, "", self.hname, jsn['src'])
                    self.sock_rep.send(msg_send)
                    self.bytes_sent = self.bytes_sent + sys.getsizeof(msg_send)

            except:
                print >> sys.stderr, "Communication error."
                print >> sys.stderr, "Message sent: ", msg_send
                print >> sys.stderr, "Message received: ", msg_recv

                raise

        return received



    def terminate_computation(self):
        """
            Node terminates computation.
        """
        self.request(comm.MSG_TERM_COMP, "")



    def terminate_all(self):
        """
            Node terminates communication.
        """
        self.request(comm.MSG_TERM_ALL, "")
