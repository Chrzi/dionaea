# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010 Mark Schloesser
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import IHandlerLoader, Timer
from dionaea.core import ihandler, incident, g_dionaea, connection
from dionaea.util import sha512file

import os
import logging
import struct
import hashlib
import json
import datetime
from time import gmtime, strftime
import gnsq

logger = logging.getLogger('nsqp')
logger.setLevel(logging.DEBUG)


# def DEBUGPERF(msg):
#	print(msg)
# logger.debug = DEBUGPERF
# logger.critical = DEBUGPERF


class NSQHandlerLoader(IHandlerLoader):
    name = "nsq"

    @classmethod
    def start(cls, config=None):
        handler = nsqihandler("*", config=config)
        return [handler]


def timestr():
    dt = datetime.datetime.now()
    my_time = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    timezone = strftime("%Z %z", gmtime())
    return my_time + " " + timezone


class nsqihandler(ihandler):

    def __init__(self, path, config=None):
        logger.debug('nsqhandler  init')
        servers = config.get('servers')
        self.connected = False
        self.ownip = config.get('own_ip', '')
        self.topic = config.get('topic', 'dionaea')
        self.topic_files = config.get('topic_files', 'dionaea.files')
        self.tls = config.get('tls')
        auth = config.get('auth')

        self.producer = gnsq.Producer(servers, tls_v1=self.tls, auth_secret=auth)

    def stop(self):
        if self.connected:
            self.producer.join()
            self.connected = False

    def publish(self, topic, **kwargs):
        if not self.connected:
            self.producer.start()
            self.connected = True
        self.producer.publish(topic, json.dumps(kwargs).encode('utf-8'), block=True, timeout=5)

    def _ownip(self, icd):
        if self.ownip:
            return self.ownip
        return icd.con.local.host

    def __del__(self):
        # self.client.close()
        pass

    def connection_publish(self, icd, con_type):
        try:
            con = icd.con
            self.publish(
                self.topic,
                icd=icd.origin,
                connection_type=con_type,
                connection_transport=con.transport,
                connection_protocol=con.protocol,
                remote_host=con.remote.host,
                remote_port=con.remote.port,
                remote_hostname=con.remote.hostname,
                local_host=self._ownip(icd),
                local_port=con.local.port
            )
        except Exception as e:
            logger.warn('exception when publishing: {0}'.format(e))

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

    def handle_incident_dionaea_download_complete_unique(self, i):
        self.handle_incident_dionaea_download_complete_again(i)
        if not hasattr(i, 'con'):
            return
        logger.debug('unique complete, publishing md5 {0}, path {1}'.format(i.md5hash, i.file))
        try:
            self.sendfile(i.file)
        except Exception as e:
            logger.warn('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_download_complete_again(self, i):
        if not hasattr(i, 'con'):
            return
        logger.debug('hash complete, publishing md5 {0}, path {1}'.format(i.md5hash, i.file))
        try:
            tstamp = timestr()
            sha512 = sha512file(i.file)
            self.publish(
                self.topic,
                icd=i.origin,
                time=tstamp,
                saddr=i.con.remote.host,
                sport=str(i.con.remote.port),
                daddr=self._ownip(i),
                dport=str(i.con.local.port),
                md5=i.md5hash,
                sha512=sha512,
                url=i.url
            )
        except Exception as e:
            logger.warn('exception when publishing: {0}'.format(e))

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
                saddr=i.con.remote.host,
                sport=str(i.con.remote.port),
                daddr=self._ownip(i),
                dport=str(i.con.local.port)
            )
        except Exception as e:
            logger.warn('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_module_emu_profile(self, icd):
        if not hasattr(icd, 'con'):
            return
        logger.debug('emu profile, publishing length {0}'.format(len(icd.profile)))
        try:
            self.publish(self.topic, icd=icd.origin, profile=icd.profile)
        except Exception as e:
            logger.warn('exception when publishing: {0}'.format(e))
