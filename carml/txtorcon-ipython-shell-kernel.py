#!/usr/bin/env python

import traceback
from IPython import InteractiveShell
from IPython.core.completer import IPCompleter
import code
import datetime
import sys
import json
import hashlib
import hmac
import uuid
from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqSubConnection, \
    ZmqREPConnection, ZmqRouterConnection

from twisted.internet import defer, reactor, task
from twisted.python.failure import Failure
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import serverFromString
from twisted.python import log
from txtorcon import build_local_tor_connection


def dprint(message):
    """ Show debug information """
    print(message)
    sys.stdout.flush()


class TwistedIPythonKernel(object):
    DELIM = b"<IDS|MSG>"

    def __init__(self, config, _locals):
        self.config = config
        self._locals = _locals
        self.zf = ZmqFactory()
        self.engine_id = str(uuid.uuid4())
        self.execution_count = 0
        self.shell = InteractiveShell(user_ns=self._locals)
        
    def get_endpoint_desc(self, port_str):
        return self.config["transport"] + "://" + self.config["ip"] + ":" + str(port_str)

    def sign(self, msg_lst):
        """
        Sign a message with a secure signature.
        """
        signature_schemes = {"hmac-sha256": hashlib.sha256}
        auth = hmac.HMAC(
            unicode(self.config["key"]).encode("ascii"),
            digestmod=signature_schemes[self.config["signature_scheme"]])
        h = auth.copy()
        for m in msg_lst:
            h.update(m)
        return h.hexdigest()

    def deserialize_wire_message(self, message):
        delim_idx = message.index(self.DELIM)
        identities = message[:delim_idx]
        m_signature = message[delim_idx + 1]
        msg_frames = message[delim_idx + 2:]

        m = {}
        m['header']        = json.loads(msg_frames[0])
        m['parent_header'] = json.loads(msg_frames[1])
        m['metadata']      = json.loads(msg_frames[2])
        m['content']       = json.loads(msg_frames[3])
        check_sig = self.sign(msg_frames)
        if check_sig != m_signature:
            raise ValueError("Signatures do not match")

        return identities, m

    def start(self):
        heartbeat_endpoint_desc = self.get_endpoint_desc(self.config['hb_port'])    
        heartbeat_endpoint = ZmqEndpoint("bind", heartbeat_endpoint_desc)
        self.heartbeat_conn = ZmqREPConnection(self.zf, heartbeat_endpoint)
        def reply_heartbeat(message_id, message):
            self.heartbeat_conn.reply(message_id, message)
        self.heartbeat_conn.gotMessage = reply_heartbeat

        iopub_endpoint_desc = self.get_endpoint_desc(self.config['iopub_port'])
        iopub_endpoint = ZmqEndpoint("bind", iopub_endpoint_desc)
        self.iopub_conn = ZmqPubConnection(self.zf, iopub_endpoint)
        def got_iopub_message(message_id, message):
            #print "iopub message %r %r" % (message_id, message)
            pass
        self.iopub_conn.gotMessage = got_iopub_message
    
        control_endpoint_desc = self.get_endpoint_desc(self.config['control_port'])
        control_endpoint = ZmqEndpoint("bind", control_endpoint_desc)
        self.control_conn = ZmqRouterConnection(self.zf, control_endpoint)
        def got_control_message(message):
            #print "control message: %r" % (message,)
            pass
        self.control_conn.messageReceived = got_control_message

        stdin_endpoint_desc = self.get_endpoint_desc(self.config['stdin_port'])
        stdin_endpoint = ZmqEndpoint("bind", stdin_endpoint_desc)
        self.stdin_conn = ZmqRouterConnection(self.zf, stdin_endpoint)
        def got_stdin_message(message):
            #print "stdin message: %r" % (message,)
            pass
        self.stdin_conn.messageReceived = got_stdin_message

        shell_endpoint_desc = self.get_endpoint_desc(self.config['shell_port'])
        shell_endpoint = ZmqEndpoint("bind", shell_endpoint_desc)
        self.shell_conn = ZmqRouterConnection(self.zf, shell_endpoint)
        self.shell_conn.messageReceived = self.shell_handler    

    def msg_id(self):
        """ Return a new uuid for message id """
        return str(uuid.uuid4())

    def new_header(self, msg_type):
        """make a new header"""
        return {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": self.msg_id(),
            "username": "kernel",
            "session": self.engine_id,
            "msg_type": msg_type,
            "version": "5.0",
        }

    def send(self, stream, msg_type, content=None, parent_header=None, metadata=None):
        header = self.new_header(msg_type)
        if content is None:
            content = {}
        if parent_header is None:
            parent_header = {}
        if metadata is None:
            metadata = {}

        msg_lst = [
            bytes(json.dumps(header)),
            bytes(json.dumps(parent_header)),
            bytes(json.dumps(metadata)),
            bytes(json.dumps(content)),
        ]
        signature = self.sign(msg_lst)
        parts = [self.DELIM,
                 signature,
                 msg_lst[0],
                 msg_lst[1],
                 msg_lst[2],
                 msg_lst[3]]
        if self.identities:
            parts = self.identities + parts
        stream.send(parts)

    def run_source_code(self, source, msg):
        try:
            my_code = code.compile_command(source)
        except NameError as e:
            dprint("name error")
            error = True
        except SyntaxError as e:
            dprint("syntax error")
            error = True
        except OverflowError as e:
            dprint("over flow error")
            error = True
        except ValueError as e:
            dprint("value error")
            error = True

        try:
            result = eval(my_code, globals(), self._locals)
        except Exception as e:
            print "eval exception"
            etype, value, tb = sys.exc_info()
            metadata = {
                "dependencies_met": True,
                "engine": self.engine_id,
                "status": "error",
                "started": datetime.datetime.now().isoformat(),
            }
            content = {
                "status": "error",
                "execution_count": self.execution_count,
                'ename' : "SyntaxError",
                'evalue' : "holy fuck",
                'traceback' : traceback.extract_tb(tb),
            }
            #print content
            traceback.print_tb(tb)
            self.send(self.shell_conn, 'execute_reply', content, metadata=metadata,
                      parent_header=msg['header'])
        else:
            content = {
                'execution_count': self.execution_count,
                'code': msg['content']["code"],
            }
            self.send(self.iopub_conn, 'execute_input', content, parent_header=msg['header'])

            if result is not None:
                content = {
                    'execution_count': self.execution_count,
                    'data': {"text/plain": str(result)},
                    'metadata': {}
                }
                self.send(self.iopub_conn, 'execute_result', content, parent_header=msg['header'])

            metadata = {
                "dependencies_met": True,
                "engine": self.engine_id,
                "status": "ok",
                "started": datetime.datetime.now().isoformat(),
            }
            content = {
                "status": "ok",
                "execution_count": self.execution_count,
                "user_variables": {},
                "payload": [],
                "user_expressions": {},
            }
            self.send(self.shell_conn, 'execute_reply', content, metadata=metadata,
                      parent_header=msg['header'])
            self.execution_count += 1

    def handle_code(self, msg):
        content = {
            'execution_state': "busy",
        }
        self.send(self.iopub_conn, 'status', content, parent_header=msg['header'])
        self.run_source_code(msg['content']["code"], msg)
        content = {
            'execution_state': "idle",
        }
        self.send(self.iopub_conn, 'status', content, parent_header=msg['header'])

    def shell_handler(self, message):
        self.identities, msg = self.deserialize_wire_message(message)
        if msg['header']["msg_type"] == "execute_request":
            self.handle_code(msg)
        elif msg['header']["msg_type"] == "kernel_info_request":
            content = {
                "protocol_version": "5.0",
                "ipython_version": [1, 1, 0, ""],
                "language_version": [0, 0, 1],
                "language": "twisted_ipython_kernel",
                "implementation": "twisted_ipython_kernel",
                "implementation_version": "1.1",
                "language_info": {
                    "name": "twisted_ipython_kernel",
                    "version": "1.0",
                    'mimetype': "",
                    'file_extension': ".py",
                    'pygments_lexer': "",
                    'codemirror_mode': "",
                    'nbconvert_exporter': "",
                },
                "banner": ""
            }
            self.send(self.shell_conn, 'kernel_info_reply', content, parent_header=msg['header'])

        elif msg['header']["msg_type"] == "history_request":
            dprint("unhandled history request")
        elif msg['header']["msg_type"] == "complete_request":
            text, matches = self.shell.complete(msg["content"][u"code"], msg["content"][u"code"], int(msg["content"][u"cursor_pos"]))
            content = {
                'matches' : matches,
                'cursor_start' : 0,
                'cursor_end' : msg["content"][u"cursor_pos"],
                'metadata' : {},
                'status' : 'ok'
            }
            self.send(self.shell_conn, 'complete_reply', content, parent_header=msg['header'])

        else:
            dprint("unknown msg_type: %r" % (msg['header']["msg_type"],))


def add_attacher(state):
    state.set_attacher(SOCKSClientStreamAttacher(state), reactor)
    return state

def main():
    if len(sys.argv) > 1:
        print "Loading simple_kernel with args:", sys.argv
        print "Reading config file '%s'..." % sys.argv[1]
        config = json.load(open(sys.argv[1]))
    else:
        print "Starting simple_kernel with default args..."
        config = {
            'control_port'      : 0,
            'hb_port'           : 0,
            'iopub_port'        : 0,
            'ip'                : '127.0.0.1',
            'key'               : str(uuid.uuid4()),
            'shell_port'        : 0,
            'signature_scheme'  : 'hmac-sha256',
            'stdin_port'        : 0,
            'transport'         : 'tcp'
        }

    #d = build_local_tor_connection(reactor)
    d = defer.succeed(None)
    def start_kernel(tor_state):
        kernel = TwistedIPythonKernel(config, locals())
        kernel.start()
    d.addCallback(start_kernel)

    reactor.run()

if __name__ == '__main__':
    main()
