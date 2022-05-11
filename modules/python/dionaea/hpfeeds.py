# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010 Mark Schloesser
#
# SPDX-License-Identifier: GPL-2.0-or-later
import base64

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

logger = logging.getLogger('hpfeeds')
logger.setLevel(logging.DEBUG)

# def DEBUGPERF(msg):
#	print(msg)
# logger.debug = DEBUGPERF
# logger.critical = DEBUGPERF

BUFSIZ = 16384

OP_ERROR = 0
OP_INFO = 1
OP_AUTH = 2
OP_PUBLISH = 3
OP_SUBSCRIBE = 4

MAXBUF = 10 * (1024 ** 2)
SIZES = {
    OP_ERROR: 5 + MAXBUF,
    OP_INFO: 5 + 256 + 20,
    OP_AUTH: 5 + 256 + 20,
    OP_PUBLISH: 5 + MAXBUF,
    OP_SUBSCRIBE: 5 + 256 * 2,
}
CONNCHAN = 'dionaea.connections'
CAPTURECHAN = 'dionaea.capture'
DCECHAN = 'dionaea.dcerpcrequests'
SCPROFCHAN = 'dionaea.shellcodeprofiles'
UNIQUECHAN = 'mwbinary.dionaea.sensorunique'


class BadClient(Exception):
    pass


class HPFeedsHandlerLoader(IHandlerLoader):
    name = "hpfeeds"

    @classmethod
    def start(cls, config=None):
        handler = hpfeedihandler("*", config=config)
        return [handler]


def timestr():
    dt = datetime.datetime.now()
    my_time = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    timezone = strftime("%Z %z", gmtime())
    return my_time + " " + timezone


# packs a string with 1 byte length field
def strpack8(x):
    if isinstance(x, str):
        x = x.encode('latin1')
    return struct.pack('!B', len(x) % 0xff) + x


# unpacks a string with 1 byte length field
def strunpack8(x):
    l = x[0]
    return x[1:1 + l], x[1 + l:]


def msghdr(op, data):
    return struct.pack('!iB', 5 + len(data), op) + data


def msgpublish(ident, chan, data):
    return msghdr(OP_PUBLISH, strpack8(ident) + strpack8(chan) + data)


def msgsubscribe(ident, chan):
    if isinstance(chan, str):
        chan = chan.encode('latin1')
    return msghdr(OP_SUBSCRIBE, strpack8(ident) + chan)


def msgauth(rand, ident, secret):
    auth_hash = hashlib.sha1(bytes(rand) + secret).digest()
    return msghdr(OP_AUTH, strpack8(ident) + auth_hash)


class FeedUnpack(object):
    def __init__(self):
        self.buf = bytearray()

    def reset(self):
        self.buf = bytearray()

    def __iter__(self):
        return self

    def __next__(self):
        return self.unpack()

    def feed(self, data):
        self.buf.extend(data)

    def unpack(self):
        if len(self.buf) < 5:
            raise StopIteration('No message.')

        ml, opcode = struct.unpack('!iB', self.buf[:5])
        if ml > SIZES.get(opcode, MAXBUF):
            raise BadClient('Not respecting MAXBUF.')

        if len(self.buf) < ml:
            raise StopIteration('No message.')

        data = self.buf[5:ml]
        del self.buf[:ml]
        return opcode, data


class hpclient(connection):
    def __init__(self, server, port, ident, secret, reconnect_timeout=10.0, queue_max_size=100):
        logger.debug('hpclient init')
        connection.__init__(self, 'tcp')
        self.unpacker = FeedUnpack()
        self.ident, self.secret = ident.encode('latin1'), secret.encode('latin1')

        self.connect(server, port)
        self.timeouts.reconnect = reconnect_timeout
        self.sendfiles = []
        self.msgqueue = []
        self.filehandle = None
        self.connected = False
        self.authenticated = False
        self.queueMax = queue_max_size

    def handle_established(self):
        self.connected = True
        logger.debug('hpclient established')

    def handle_io_in(self, indata):
        self.unpacker.feed(indata)

        # if we are currently streaming a file, delay handling incoming messages
        if self.filehandle:
            return len(indata)

        try:
            for opcode, data in self.unpacker:
                logger.debug('hpclient msg opcode {0} data {1}'.format(opcode, data))
                if opcode == OP_INFO:
                    name, rand = strunpack8(data)
                    logger.debug('hpclient server name {0} rand {1}'.format(name, rand))
                    self.send(msgauth(rand, self.ident, self.secret))
                    self.authenticated = True
                    self.handle_io_out()

                elif opcode == OP_PUBLISH:
                    ident, data = strunpack8(data)
                    chan, data = strunpack8(data)
                    logger.debug('publish to {0} by {1}: {2}'.format(chan, ident, data))

                elif opcode == OP_ERROR:
                    logger.debug('errormessage from server: {0}'.format(data))
                else:
                    logger.debug('unknown opcode message: {0}'.format(opcode))
        except BadClient:
            logger.error('unpacker error, disconnecting.')
            self.close()

        return len(indata)

    def handle_io_out(self):
        if not self.authenticated:
            return

        if self.filehandle:
            self.sendfiledata()
        else:
            if self.msgqueue:
                m = self.msgqueue.pop(0)
                self.send(m)

    def publish(self, channel, **kwargs):
        if self.filehandle or not self.authenticated:
            if len(self.msgqueue) >= self.queueMax:
                logger.warning('Discarding message because queue is full!')
                return
            self.msgqueue.append(
                msgpublish(self.ident, channel, json.dumps(kwargs).encode('latin1'))
            )
        else:
            self.send(
                msgpublish(self.ident, channel, json.dumps(kwargs).encode('latin1'))
            )

    def sendfile(self, filepath):
        # does not read complete binary into memory, read and send chunks
        if not self.filehandle or not self.authenticated:
            self.sendfileheader(filepath)
            self.sendfiledata()
        else:
            self.sendfiles.append(filepath)

    def sendfileheader(self, filepath):
        self.filehandle = open(filepath, 'rb')
        fsize = os.stat(filepath).st_size
        headc = strpack8(self.ident) + strpack8(UNIQUECHAN)
        headh = struct.pack('!iB', 5 + len(headc) + fsize, OP_PUBLISH)
        self.send(headh + headc)

    def sendfiledata(self):
        tmp = self.filehandle.read(BUFSIZ)
        if not tmp:
            if self.sendfiles:
                fp = self.sendfiles.pop(0)
                self.sendfileheader(fp)
            else:
                self.filehandle = None
                self.handle_io_in(b'')
        else:
            self.send(tmp)

    def handle_timeout_idle(self):
        pass

    def _reset_connection_state(self):
        self.connected = False
        self.authenticated = False
        self.filehandle = None
        self.unpacker.reset()

    def handle_disconnect(self):
        logger.info('hpclient disconnect')
        self._reset_connection_state()
        return 1

    def handle_error(self, err):
        logger.warn(str(err))
        self._reset_connection_state()
        return 1


class hpfeedihandler(ihandler):
    default_reconnect_timeout = 10.0
    default_port = 10000

    def __init__(self, path, config=None):
        logger.debug('hpfeedhandler init')

        server = os.getenv('HPFEEDS_SERVER', config['server'])
        port = os.getenv('HPFEEDS_PORT', config.get('port', self.default_port))
        ident = os.getenv('HPFEEDS_IDENT', config['ident'])
        secret = os.getenv('HPFEEDS_SECRET', config['secret'])
        self.channel = os.getenv('HPFEEDS_CHANNEL', config['channel'])
        reconnect_timeout = os.getenv('HPFEEDS_TIMEOUT', config.get('reconnect_timeout', self.default_reconnect_timeout))

        try:
            reconnect_timeout = float(reconnect_timeout)
        except (TypeError, ValueError) as e:
            logger.warn("Unable to convert value '%s' for reconnect timeout to float" % reconnect_timeout)
            reconnect_timeout = self.default_reconnect_timeout

        try:
            port = int(port)
        except (TypeError, ValueError) as e:
            logger.warn("Unable to convert value '%s' for port to int" % port)
            port = self.default_port

        self.client = hpclient(
            server,
            port,
            ident,
            secret,
            reconnect_timeout=reconnect_timeout
        )
        ihandler.__init__(self, path)
        self.ownip = config.get('own_ip', '')

    def stop(self):
        pass

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
            self.client.publish(
                self.channel,
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
            self.client.publish(
                self.channel,
                icd=icd.origin,
                con_transport=con.transport,
                con_protocol=con.protocol,
                src_addr=con.remote.host,
                src_port=con.remote.port,
                src_name=con.remote.hostname,
                dst_addr=self._ownip(icd),
                dst_port=con.local.port,
                username=self._prepare_value(icd.username),
                password=self._prepare_value(icd.password)
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
            buf = fh.read(MAXBUF / 2)

            sha512 = sha512file(i.file)
            self.client.publish(
                self.channel,
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
            self.client.publish(
                self.channel,
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
            self.client.publish(
                self.channel,
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
            self.client.publish(
                self.channel,
                icd=icd.origin,
                src_addr=icd.con.remote.host,
                src_port=icd.con.remote.port,
                dst_addr=self._ownip(icd),
                dst_port=icd.con.local.port,
                profile=icd.profile
            )
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
        self.client.publish(self.channel, **data)

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
        self.client.publish(self.channel, **data)

    def handle_incident_dionaea_modules_python_ftp_login(self, icd):
        if not hasattr(icd, 'con'):
            return
        self.login_publish(icd)

    def handle_incident_dionaea_modules_python_ftp_command(self, icd):
        if not hasattr(icd, 'con'):
            return
        data = self.command_serialize(icd, icd.command, icd.arguments)
        self.client.publish(self.channel, **data)

