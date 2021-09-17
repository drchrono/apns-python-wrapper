# Copyright 2009-2011 Max Klymyshyn, Sonettic
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import socket
from socket import SHUT_RDWR
import subprocess

from .apnsexceptions import *
from .utils import *


__all__ = ('APNSConnectionContext', 'OpenSSLCommandLine', \
           'APNSConnection', 'SSLModuleConnection')


class APNSConnectionContext(object):
    """Abstract class to implement SSL secured connection factory object"""
    certificate = None
    passphrase = None

    def __init__(self, certificate=None, passphrase=None):
        self.certificate = certificate
        self.passphrase = passphrase

    def connect(self, host, port):
        raise APNSNotImplementedMethod("APNSConnectionContext.connect ssl "\
                                        "method not implemented in context")

    def fileno(self):
        raise APNSNotImplementedMethod("APNSConnectionContext.fileno "\
                                        "method not implemented")

    def write(self, data=None):
        raise APNSNotImplementedMethod("APNSConnectionContext.write "\
                                        "method not implemented")

    def pending(self):
        raise APNSNotImplementedMethod("APNSConnectionContext.pending method "\
                                        "not implemented")

    def read(self):
        raise APNSNotImplementedMethod("APNSConnectionContext.read method "\
                                        "not implemented")

    def shutdown(self):
        raise APNSNotImplementedMethod("APNSConnectionContext.shutdown method "\
                                        "not implemented")

    def stdin(self):
        raise APNSNotImplementedMethod("APNSConnectionContext.stdin method "\
                                        "not implemented")

    def stdout(self):
        raise APNSNotImplementedMethod("APNSConnectionContext.stdout method "\
                                        "not implemented")

    def close(self):
        raise APNSNotImplementedMethod("APNSConnectionContext.close method "\
                                        "not implemented")


class OpenSSLCommandLine(APNSConnectionContext):
    """
    This class execute and send data with openssl command line tool
    """

    certificate = None
    host = None
    port = None
    executable = None
    debug = False
    passphrase = None
    pipe = None

    def __init__(self, certificate=None, executable=None, debug=False, passphrase=None):
        self.certificate = certificate
        self.executable = executable
        self.debug = debug
        self.passphrase = passphrase

    def _command(self):
        if self.passphrase:
            pass_text = "-pass file:%(passphrase)s" % {'passphrase': self.passphrase}
        else:
            pass_text = ""

        command = "%(executable)s s_client -quiet -ssl3 -cert "\
                    "%(cert)s -connect %(host)s:%(port)s"\
                    " %(passphrase)s" % {
            'executable': self.executable,
            'cert': self.certificate,
            'host': self.host,
            'port': self.port,
            'passphrase': pass_text,
            }

        return subprocess.Popen(command.split(' '), \
                            shell=False, bufsize=256, \
                            stdin=subprocess.PIPE, \
                            stdout=subprocess.PIPE, \
                            stderr=subprocess.PIPE)

    def stdin(self):
        """
        Return the file descriptor for writing to the underlying pipe
        """
        return self.pipe.stdin.fileno()

    def stdout(self):
        """
        Return the file descriptor for reading from the underlying pipe
        """
        return self.pipe.stdout.fileno()

    def connect(self, host, port):
        self.host = host
        self.port = port
        self.pipe = self._command()
        return True

    def write(self, data=None):
        """
        Write data to the connection.  We pretend all data has been
        written to the connection because the pipe provides no
        feedback on how much data was written.  It's possible this 
        could lead to failure to detect push notifications that don't
        go through.
        """
        self.pipe.stdin.write(data)
        self.pipe.stdin.flush()
        return len(data)

    def pending(self):
        return 0

    def read(self, blockSize=1024):
        return self.pipe.stdout.read()

    def context(self):
        return self

    def shutdown(self, how=SHUT_RDWR):
        self.pipe.terminate()
        self.pipe.wait()
        pass

    def close(self):
        self.pipe.terminate()
        self.pipe.wait()

class M2CryptoModuleConnection(APNSConnectionContext):
    """
    This is class which implement APNS connection based on
    "M2Crypto" module.
    """

    socket = None
    certificate = None
    connectionContext = None
    ssl_module = None
    passphrase = None
    connected = False

    def __init__(self, certificate=None, ssl_module=None, passphrase=None):
        self.socket = None
        self.connectionContext = None
        self.certificate = certificate
        self.ssl_module = ssl_module
        self.passphrase = passphrase

    def context(self):
        """
        Initialize SSL context.
        """
        if self.connectionContext != None:
            return self

        try:
            self.socket = socket.socket()
            ctx = self.ssl_module.Context('sslv3')
            if self.passphrase:
                ctx.load_cert(self.certificate, callback=lambda *args:open(self.passphrase, 'r').readline().strip())
            else:
                ctx.load_cert(self.certificate)
            self.connectionContext = self.ssl_module.Connection(ctx, sock=self.socket)
        except SSLError as e:
            raise APNSSSLError(m2_error=e)

        return self

    def certificate(self, path):
        self.certificate = path
        return self

    def passphrase(self, path):
        self.passphrase = path
        return self

    def fileno(self):
        """
        Return the file descriptor for the underlying socket.
        """
        return self.socket.fileno()

    def stdin(self):
        """
        Return the file descriptor for writing to the underlying socket
        """
        return self.fileno()

    def stdout(self):
        """
        Return the file descriptor for reading from the underlying socket
        """
        return self.fileno()

    def pending(self):
        """
        Find out how many octets are waiting to be read from
        the connection.
        """
        try:
            return self.connectionContext.pending()
        except SSLError as e:
            raise APNSSSLError(m2_error=e)

    def read(self, blockSize=1024):
        """
        Read data from the socket.
        """
        try:
            return self.connectionContext.read(blockSize)
        except SSLError as e:
            raise APNSSSLError(m2_error=e)

    def write(self, data=None):
        """
        Write data to the socket.
        """
        try:
            return self.connectionContext.write(data)
        except SSLError as e:
            raise APNSSSLError(m2_error=e)

    def connect(self, host, port):
        """
        Make connection to the host and port.
        """

        try:
            rc  = self.connectionContext.connect((host, port))
        except SSLError as e:
            self.connected = False
            raise APNSSSLError(m2_error=e)

        if rc == 0:
            self.connected = True
        else:
            self.conected = False
        return self.connected

    def shutdown(self, how=SHUT_RDWR):
        """
        Shutdown the socket.
        """
        try:
            self.socket.shutdown(how)
        except SSLError as e:
            raise APNSSSLError(m2_error=e)

    def close(self):
        """
        Close connection.
        """
        try:
            self.connectionContext.close()
            self.socket.close()
        except SSLError as e:
            raise APNSSSLError(m2_error=e)


class SSLModuleConnection(APNSConnectionContext):
    """
    This is class which implement APNS connection based on
    "ssl" module.
    """

    socket = None
    certificate = None
    connectionContext = None
    ssl_module = None
    passphrase = None
    connected = False

    def __init__(self, certificate=None, ssl_module=None, passphrase=None):
        self.socket = None
        self.connectionContext = None
        self.certificate = certificate
        self.ssl_module = ssl_module
        self.passphrase = passphrase

    def context(self):
        """
        Initialize SSL context.
        """
        if self.connectionContext != None:
            return self

        self.socket = socket.socket()
        self.connectionContext = self.ssl_module.wrap_socket(\
                        self.socket,
                        ssl_version=self.ssl_module.PROTOCOL_SSLv3,
                        certfile=self.certificate)

        if self.passphrase:
            self.connectionContext.context.load_cert_chain(certfile=self.certificate,
                                                    password=open(self.passphrase, 'r').readLine().trim())

        return self

    def certificate(self, path):
        self.certificate = path
        return self

    def passphrase(self, path):
        self.passphrase = path
        return self

    def fileno(self):
        """
        Return the file descriptor for the underlying socket.
        """
        return self.socket.fileno()

    def stdin(self):
        """
        Return the file descriptor for writing to the underlying socket
        """
        return self.fileno()

    def stdout(self):
        """
        Return the file descriptor for reading from the underlying socket
        """
        return self.fileno()

    def pending(self):
        """
        Find out how many octets are waiting to be read from
        the connection.
        """

        return self.connectionContext.pending()

    def read(self, blockSize=1024):
        """
        Make connection to the host and port.
        """

        return self.connectionContext.read(blockSize)

    def write(self, data=None):
        """
        Make connection to the host and port.
        """
        print self.connectionContext
        return self.connectionContext.write(data)

    def connect(self, host, port):
        """
        Make connection to the host and port.
        """

        try:
            self.connected = self.connectionContext.connect_ex((host, port))
        except:
            self.conected = False
        return self.connected

    def shutdown(self, how=SHUT_RDWR):
        """
        Shutdown the socket.
        """
        self.socket.shutdown(how)

    def close(self):
        """
        Close connection.
        """
        self.connectionContext.close()
        self.socket.close()
        self.connected = False


class APNSConnection(APNSConnectionContext):
    """
    APNSConnection wrap SSL connection to the Apple Push Notification Server.
    """

    debug = False
    connectionContext = None

    def __init__(self, certificate=None,
                        ssl_command="openssl",
                        force_ssl_command=False,
                        disable_executable_search=False,
                        debug=False,
                        passphrase=None):
        self.connectionContext = None
        self.debug = debug

        if not os.path.exists(str(certificate)):
            raise APNSCertificateNotFoundError("Apple Push Notification "\
                "Service Certificate file %s not found." % str(certificate))

        if passphrase:
            if not os.path.exists(str(passphrase)):
                raise APNSPassphraseNotFoundError("Apple Push Notification "\
                    "Service passphrase file %s not found." % str(passphrase))

        try:
            if force_ssl_command:
                raise APNSForceOpenSSLError("There is force_ssl_command "\
                                    "forces command line tool")

            import sys
            if sys.version_info < (3,2): #use M2Crypto if we dont have python 3.2 or newer
                from M2Crypto import SSL as ssl_module
                self.connectionContext = M2CryptoModuleConnection(certificate, \
                                                            ssl_module=ssl_module, \
                                                            passphrase=passphrase)
            else:
                # use ssl library to handle secure connection
                import ssl as ssl_module
                self.connectionContext = SSLModuleConnection(certificate, \
                                            ssl_module=ssl_module, \
                                            passphrase=passphrase)
        except APNSForceOpenSSLError:
            # use command line openssl tool to handle secure connection
            if not disable_executable_search:
                executable = find_executable(ssl_command)
            else:
                executable = ssl_command

            if not executable:
                raise APNSNoCommandFound("SSL Executable [%s] not found in "\
                                "your PATH environment" % str(ssl_command))

            self.connectionContext = OpenSSLCommandLine(certificate, \
                                                    executable, debug=debug, \
                                                    passphrase=passphrase)
        except ImportError:
            raise APNSM2CryptoMissingError("You do not have M2Crypto installed."\
                                            "Either upgrade your python version to 3.2 or "\
                                            "install M2Crypto")

        self.certificate = str(certificate)
        self.passphrase = str(passphrase)

    def stdin(self):
        return self.context().stdin()

    def stdout(self):
        return self.context().stdout()

    def connect(self, host, port):
        """
        Make connection to the host and port.
        """
        self.context().connect(host, port)
        return self

    def certificate(self, path):
        self.context().certificate(path)
        return self

    def passphrase(self, path):
        self.context().passphrase(path)
        return self

    def fileno(self):
        return self.context().fileno()

    def write(self, data=None):
        return self.context().write(data)

    def pending(self):
        return self.context().pending()

    def read(self, blockSize=1024):
        return self.context().read(blockSize)

    def context(self):
        if not self.connectionContext:
            raise APNSNoSSLContextFound("There is no SSL context available "\
                                            "in your python environment.")
        return self.connectionContext.context()

    def shutdown(self):
        self.context().shutdown()

    def close(self):
        """
        Close connection.
        """
        self.context().close()
