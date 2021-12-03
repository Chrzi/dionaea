# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010 Mark Schloesser
#
# SPDX-License-Identifier: GPL-2.0-or-later
import ast
import asyncio
import base64
import threading

from dionaea import IHandlerLoader, Timer
from dionaea.core import ihandler, incident, g_dionaea, connection
from dionaea.util import sha512file

import os
import logging
import json
from datetime import datetime
import nsq
import tornado
import uuid

logger = logging.getLogger('nsq')
logger.setLevel(logging.DEBUG)

MAX_SIZE = 10 * 1024 * 1024


#def DEBUGPERF(msg):
#    print(msg)
#logger.debug = DEBUGPERF
#logger.critical = DEBUGPERF


class NSQHandlerLoader(IHandlerLoader):
    name = "nsq"

    @classmethod
    def start(cls, config=None):
        handler = nsqihandler("*", config=config)
        return [handler]


def time():
    return datetime.utcnow().isoformat()


class nsqihandler(ihandler):

    def __init__(self, path, config=None):
        logger.debug('nsqhandler  init')

        logger.debug("getting config")
        servers = ast.literal_eval(config.get('servers'))
        self.ownip = config.get('own_ip', '')
        self.topic = config.get('topic', 'dionaea')
        self.topic_files = config.get('topic_files', 'dionaea.files')
        self.tls = config.get('tls') == 'True'
        auth = config.get('auth', '')
        logger.debug("got config")
        logger.debug("Using server {} with topic {} and tls {}".format(servers, self.topic, self.tls))
        self.seq = 0
        self.uuid = uuid.uuid4()

        self.writer: nsq.Writer

        def run():
            # Create new event loop and start it manually
            # tornado.ioloop.IOLoop.current() should create a new asyncio event loop, but nope
            # Because this is in a new Thread, this thread has no event loop
            l = asyncio.new_event_loop()
            asyncio.set_event_loop(l)

            # Use the newly created asyncio event loop and create a tornado ioloop based on that
            loop = tornado.ioloop.IOLoop.current()
            loop.make_current()

            if auth == '':
                logger.debug("Auth is not set")
                self.writer = nsq.Writer(servers, tls_v1=self.tls)
            else:
                logger.debug("Auth is set")
                self.writer = nsq.Writer(servers, tls_v1=self.tls, auth_secret=auth.encode('utf-8'))
            # start the loop, not calling nsq.run() because registering handlers for Signals is not supported other than
            # in the main thread
            loop.start()

        ihandler.__init__(self, path)
        self.thread = threading.Thread(target=run).start()

    def stop(self):
        logger.info("Stopping producer.")
        self.writer.io_loop.stop()

    def publish(self, topic, **kwargs):
        kwargs["time"] = time()
        msg = json.dumps(kwargs)
        wrapped = json.dumps({
            "seq": self.seq,
            "connection": str(self.uuid),
            "data": base64.b64encode(msg.encode("utf-8", errors="ignore")).decode("ascii")
        })
        self.seq += 1
        self.writer.pub(topic, wrapped.encode())

    def _ownip(self, icd):
        if self.ownip:
            return self.ownip
        return icd.con.local.host

    def __del__(self):
        # self.client.close()
        pass

    def _prepare_value(self, v):
        """
        Prepare value to be JSON compatible.

        :param v: The value to prepare.
        :return: The prepared value
        """
        if isinstance(v, bytes):
            return v.decode(encoding="utf-8", errors="replace")
        elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], bytes):
            return [x.decode(encoding="utf-8", errors="replace") for x in v]
        return v

    def connection_publish(self, icd, con_type):
        try:
            con = icd.con
            self.publish(
                self.topic,
                icd=icd.origin,
                con_type=con_type,
                con_transport=con.transport,
                con_protocol=con.protocol,
                src_addr=con.remote.host,
                src_port=con.remote.port,
                src_name=con.remote.hostname,
                dst_addr=self._ownip(icd),
                dst_dport=con.local.port
            )
        except Exception as e:
            logger.warning('exception when publishing', exc_info=e)

    def command_serialize(self, icd, cmd, args):
        con = icd.con
        data = {
            "icd": icd.origin,
            "con_transport": con.transport,
            "con_protocol": con.protocol,
            "src_addr": con.remote.host,
            "src_port": con.remote.port,
            "src_name": con.remote.hostname,
            "dst_addr": self._ownip(icd),
            "dst_port": con.local.port,
            "cmd": self._prepare_value(cmd)
        }
        if args:
            data["args"] = self._prepare_value(args)
        return data

    def login_publish(self, icd):
        try:
            con = icd.con
            self.publish(
                self.topic,
                icd=icd.origin,
                con_transport=con.transport,
                con_protocol=con.protocol,
                src_addr=con.remote.host,
                src_port=con.remote.port,
                src_name=con.remote.hostname,
                dst_addr=self._ownip(icd),
                dst_port=con.local.port,
                username=self._prepare_value(icd.username),
                pasword=self._prepare_value(icd.password)
            )
        except Exception as e:
            logger.warning('exception when publishing', exc_info=e)

    def handle_incident(self, i):
        pass

    def handle_incident_dionaea_connection_tcp_listen(self, icd):
        self.connection_publish(icd, 'listen')
        con = icd.con
        logger.info("listen connection on %s:%i" %
                    (con.remote.host, con.remote.port))

    def handle_incident_dionaea_connection_tls_listen(self, icd):
        self.connection_publish(icd, 'listen')
        con = icd.con
        logger.info("listen connection on %s:%i" %
                    (con.remote.host, con.remote.port))

    def handle_incident_dionaea_connection_tcp_connect(self, icd):
        self.connection_publish(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" %
                    (con.remote.host, con.remote.hostname, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tls_connect(self, icd):
        self.connection_publish(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" %
                    (con.remote.host, con.remote.hostname, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_udp_connect(self, icd):
        self.connection_publish(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" %
                    (con.remote.host, con.remote.hostname, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tcp_accept(self, icd):
        self.connection_publish(icd, 'accept')
        con = icd.con
        logger.info("accepted connection from  %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tls_accept(self, icd):
        self.connection_publish(icd, 'accept')
        con = icd.con
        logger.info("accepted connection from %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tcp_reject(self, icd):
        self.connection_publish(icd, 'reject')
        con = icd.con
        logger.info("reject connection from %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tcp_pending(self, icd):
        self.connection_publish(icd, 'pending')
        con = icd.con
        logger.info("pending connection from %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_free(self, icd):
        self.connection_publish(icd, 'free')
        con = icd.con
        logger.info("freed connection from %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_download_complete_unique(self, i):
        if not hasattr(i, 'con'):
            return
        logger.debug('unique complete, publishing md5 {0}, path {1}'.format(i.md5hash, i.file))
        try:
            size = os.path.getsize(i.file)
            fh = open(i.file, 'rb')
            buf = fh.read(MAX_SIZE)

            sha512 = sha512file(i.file)
            self.publish(
                self.topic,
                icd=i.origin,
                src_addr=i.con.remote.host,
                src_port=i.con.remote.port,
                dst_addr=self._ownip(i),
                dst_port=i.con.local.port,
                url=i.url,
                md5=i.md5hash,
                sha512=sha512,
                size=size,
                data=base64.b64encode(buf).decode("ascii")
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_download_complete_again(self, i):
        if not hasattr(i, 'con'):
            return
        logger.debug('hash complete, publishing md5 {0}, path {1}'.format(i.md5hash, i.file))
        try:
            sha512 = sha512file(i.file)
            self.publish(
                self.topic,
                icd=i.origin,
                src_addr=i.con.remote.host,
                src_port=i.con.remote.port,
                dst_addr=self._ownip(i),
                dst_port=i.con.local.port,
                md5=i.md5hash,
                sha512=sha512,
                url=i.url
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, i):
        if not hasattr(i, 'con'):
            return
        logger.debug('dcerpc request, publishing uuid {0}, opnum {1}'.format(i.uuid, i.opnum))
        try:
            self.publish(
                self.topic,
                icd=i.origin,
                uuid=i.uuid,
                opnum=i.opnum,
                src_addr=i.con.remote.host,
                src_port=str(i.con.remote.port),
                dst_addr=self._ownip(i),
                dst_port=str(i.con.local.port)
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_module_emu_profile(self, icd):
        if not hasattr(icd, 'con'):
            return
        logger.debug('emu profile, publishing length {0}'.format(len(icd.profile)))
        try:
            self.publish(self.topic, icd=icd.origin, profile=icd.profile)
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_mssql_login(self, icd):
        if not hasattr(icd, 'con'):
            return
        self.login_publish(icd)

    def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
        if not hasattr(icd, 'con'):
            return
        data = self.command_serialize(icd, icd.cmd, None)
        self.publish(self.topic, **data)

    def handle_incident_dionaea_modules_python_mysql_login(self, icd):
        if not hasattr(icd, 'con'):
            return
        self.login_publish(icd)

    def handle_incident_dionaea_modules_python_mysql_command(self, icd):
        if not hasattr(icd, 'con'):
            return
        if hasattr(icd, 'args'):
            data = self.command_serialize(icd, icd.cmd, icd.args)
        else:
            data = self.command_serialize(icd, icd.command, None)
        self.publish(self.topic, **data)

    def handle_incident_dionaea_modules_python_ftp_login(self, icd):
        if not hasattr(icd, 'con'):
            return
        self.login_publish(icd)

    def handle_incident_dionaea_modules_python_ftp_command(self, icd):
        if not hasattr(icd, 'con'):
            return
        data = self.command_serialize(icd, icd.command, icd.arguments)
        self.publish(self.topic, **data)
