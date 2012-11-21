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


import struct
import base64
import binascii

from __init__ import *
from connection import *
from apnsexceptions import *
from utils import _doublequote
from select import select

NULL = 'null'


__all__ = ('APNSAlert', 'APNSProperty', 'APNSNotificationWrapper', \
           'APNSNotification')


class APNSAlert(object):
    """
    This is an object to generate properly APNS alert object with
    all possible values.
    """
    def __init__(self):
        self.alertBody = None
        self.actionLocKey = None
        self.locKey = None
        self.locArgs = None

    def body(self, alertBody):
        """
        The text of the alert message.
        """
        if alertBody and not isinstance(alertBody, str):
            raise APNSValueError("Unexpected value of argument. "\
                                    "It should be string or None.")

        self.alertBody = alertBody
        return self

    def action_loc_key(self, alk=NULL):
        """
        If a string is specified, displays an alert with two buttons.
        """
        if alk and not isinstance(alk, str):
            raise APNSValueError("Unexpected value of argument. "\
                                    "It should be string or None.")

        self.actionLocKey = alk
        return self

    def loc_key(self, lk):
        """
        A key to an alert-message string in a
        Localizable.strings file for the current
        localization (which is set by the user's language preference).
        """
        if lk and not isinstance(lk, str):
            raise APNSValueError("Unexcpected value of argument. "\
                                        "It should be string or None")
        self.locKey = lk
        return self

    def loc_args(self, la):
        """
        Variable string values to appear in place of
        the format specifiers in loc-key.
        """

        if la and not isinstance(la, (list, tuple)):
            raise APNSValueError("Unexpected type of argument. "\
                                    "It should be list or tuple of strings")

        self.locArgs = ['"%s"' % str(x) for x in la]
        return self

    def build(self):
        """
        Build object to JSON Apple Push Notification Service string.
        """

        arguments = []
        if self.alertBody:
            arguments.append('"body":"%s"' % _doublequote(self.alertBody))

        if self.actionLocKey:
            arguments.append('"action-loc-key":"%s"' % _doublequote(\
                                                        self.actionLocKey))

        if self.locKey:
            arguments.append('"loc-key":"%s"' % _doublequote(self.locKey))

        if self.locArgs:
            arguments.append('"loc-args":[%s]' % ",".join(self.locArgs))

        return ",".join(arguments)


class APNSProperty(object):
    """
    This class should describe APNS arguments.
    """
    name = None
    data = None

    def __init__(self, name=None, data=None):
        if not name or not isinstance(name, str) or len(name) == 0:
            raise APNSValueError("Name of property argument "\
                                    "should be a non-empry string")

        if not isinstance(data, (int, str, list, tuple, float)):
            raise APNSValueError("Data argument should be string, "\
                                                "number, list of tuple")

        self.name = name
        self.data = data

    def build(self):
        """Build property for payload"""
        arguments = []
        name = '"%s":' % self.name

        if isinstance(self.data, (int, float)):
            return "%s%s" % (name, str(self.data))

        if isinstance(self.data, str) or isinstance(self.data, unicode):
            return '%s"%s"' % (name, _doublequote(self.data))

        if isinstance(self.data, (tuple, list)):
            arguments = map(lambda x: if_else(isinstance(x, str), \
                            '"%s"' % _doublequote(str(x)), str(x)), self.data)
            return "%s[%s]" % (name, ",".join(arguments))

        return '%s%s' % (name, NULL)


class APNSNotificationWrapper(object):
    """
    This object wrap a list of APNS tuples. You should use
    .append method to add notifications to the list. By usint
    method .notify() all notification will send to the APNS server.
    """
    sandbox = True
    apnsHost = 'gateway.push.apple.com'
    apnsSandboxHost = 'gateway.sandbox.push.apple.com'
    apnsPort = 2195
    payloads = None
    connection = None
    debug_ssl = False
    current_wrapper_id = 0
    timeout = 60
    read_buf = []

    def __init__(self, certificate=None, sandbox=True, debug_ssl=False, \
                    force_ssl_command=False, passphrase=None):
        self.debug_ssl = debug_ssl
        self.connection = APNSConnection(certificate=certificate, \
                            force_ssl_command=force_ssl_command, \
                            debug=self.debug_ssl, \
                            passphrase=passphrase)
        self.sandbox = sandbox
        self.payloads = []

    def append(self, payload=None):
        """Append payload to wrapper"""
        if not isinstance(payload, APNSNotification):
            raise APNSTypeError("Unexpected argument type. Argument should "\
                                "be an instance of APNSNotification object")
        self.payloads.append(payload)

    def count(self):
        """Get count of payloads
        """
        return len(self.payloads)

    def connect(self):
        """Make connection to APNS server"""

        if self.sandbox != True:
            apnsHost = self.apnsHost
        else:
            apnsHost = self.apnsSandboxHost

        self.connection.connect(apnsHost, self.apnsPort)

    def read(self, blockSize=1024):
        buf = self.connection.read(blockSize=blockSize)
        self.read_buf.append(buf)
        return len(buf)

    def disconnect(self):
        """Close connection ton APNS server"""
        self.connection.shutdown()
        self.connection.close()

    def next_wrapper_id(self):
        self.current_wrapper_id += 1
        return self.current_wrapper_id

    def notify(self):
        """
        Send nofification to APNS:
            1) prepare all internal variables to APNS Payout JSON
            2) send notification
        """
        sent_notifications = []
        payloads = [o.payload(wrapper_id=self.next_wrapper_id()) for o in self.payloads]
        messages = []

        if len(payloads) == 0:
            return sent_notifications

        if self.sandbox != True:
            apnsHost = self.apnsHost
        else:
            apnsHost = self.apnsSandboxHost

        error_detected = False
        if self.connection.connect(apnsHost, self.apnsPort):
            rfds = [self.connection.fileno()]
            wfds = [self.connection.fileno()]
            efds = [self.connection.fileno()]

            payloads.reverse()
            done = False
            current_payload = payloads.pop()
            while not done:
                ready_to_read, ready_to_write, in_error = select(rfds, wfds, efds, self.timeout)

                # Handle errors
                if len(in_error):
                    print "Error"
                    pass
                
                # Read from APNS
                if len(ready_to_read):
                    n_read = self.read()
                    if len(self.read_buf) and len(self.read_buf[0]) >= 6:
                        print "Dropping out"
                        error_detected = True
                        break

                # Write to APNS
                if len(ready_to_write):
                    w_fd = ready_to_write[0]
                    current_payload.write(self.connection)

                if current_payload.sent:
                    sent_notifications.append((current_payload.wrapper_id, current_payload.global_id))
                    if len(payloads):
                        current_payload = payloads.pop()
                    else:
                        done = True

            ready_to_read, ready_to_write, in_error = select(rfds, [], [], 15)
            if len(ready_to_read):
                n_read = self.read()
                error_detected = True

        if error_detected:
            print "self.read_buf=", self.read_buf
            cmd, status, identifier = struct.unpack("!BBL", self.read_buf[0])
            for i, (wrapper_id, global_id) in enumerate(sent_notifications):
                if wrapper_id == identifier:
                    sent_notifications = sent_notifications[:i]
                    break
            print "identifier=%d" % (identifier)
            print sent_notifications

        try:
            self.disconnect()
        except:
            pass

        return [l[1] for l in sent_notifications]


class APNSNotification(object):
    """
    APNSNotificationWrapper wrap Apple Push Notification Service into
    python object.
    """

    global_id = 0        # Assigned by the caller
    wrapper_id = 0       # Assigned by the library

    command = 1
    identifier = 0 
    expiry = 0
    badge = None
    sound = None
    alert = None
    n_written = 0
    msg_len = 0
    sent = False

    deviceToken = None

    maxPayloadLength = 256
    deviceTokenLength = 32

    properties = None

    def __init__(self, use_enhanced_format=True, global_id=0):
        """
        Initialization of the APNSNotificationWrapper object.
        
        use_enhanded_format -- If true, then use the enhanced
          APNS message format.  Otherwise, use the original APNS
          message format.
        global_id -- Unique identifier within the caller's context.
        """
        self.command = int(use_enhanced_format)
        self.properties = []
        self.badgeValue = None
        self.soundValue = None
        self.alertObject = None
        self.deviceToken = None
        self.global_id = global_id
        self.n_written = 0
        self.msg_len = 0
        self.sent = False

    def token(self, token):
        """
        Add deviceToken in binary format.
        """
        self.deviceToken = token
        return self

    def tokenBase64(self, encodedToken):
        """
        Add deviceToken as base64 encoded string (not binary)
        """
        self.deviceToken = base64.standard_b64decode(encodedToken)
        return self

    def tokenHex(self, hexToken):
        """
        Add deviceToken as a hexToken
        Strips out whitespace and <>
        """
        hexToken = hexToken.strip().strip(\
                    '<>').replace(' ', '').replace('-', '')
        self.deviceToken = binascii.unhexlify(hexToken)

        return self

    def unbadge(self):
        """Simple shorcut to remove badge from your application.
        """
        self.badge(0)
        return self

    def badge(self, num=None):
        """
        Add badge to the notification. If argument is
        None (by default it is None)
        badge will be disabled.
        """
        if num == None:
            self.badgeValue = None
            return self

        if not isinstance(num, int):
            raise APNSValueError("Badge argument must be a number")
        self.badgeValue = num
        return self

    def sound(self, sound='default'):
        """
        Add a custom sound to the noficitaion.
        By defailt it is default sound ('default')
        """
        if sound == None:
            self.soundValue = None
            return self
        self.soundValue = str(sound)
        return self

    def alert(self, alert=None):
        """
        Add an alert to the Wrapper. It should be string or
        APNSAlert object instance.
        """
        if not isinstance(alert, str) and not isinstance(alert, unicode) and \
            not isinstance(alert, APNSAlert):
            raise APNSTypeError("Wrong type of alert argument. Argument s"\
                                "hould be String, Unicode string or an "\
                                "instance of APNSAlert object")
        self.alertObject = alert
        return self

    def appendProperty(self, *args):
        """
        Add a custom property to list of properties.
        """
        for prop in args:
            if not isinstance(prop, APNSProperty):
                raise APNSTypeError("Wrong type of argument. Argument should"\
                                    " be an instance of APNSProperty object")
            self.properties.append(prop)
        return self

    def clearProperties(self):
        """
        Clear list of properties.
        """
        self.properties = None

    def build(self):
        """
        Build all notifications items to one string.
        """
        keys = []
        apsKeys = []
        if self.soundValue:
            apsKeys.append('"sound":"%s"' % _doublequote(self.soundValue))

        if self.badgeValue:
            apsKeys.append('"badge":%d' % int(self.badgeValue))

        if self.alertObject != None:
            alertArgument = ""
            if isinstance(self.alertObject, str):
                alertArgument = _doublequote(self.alertObject)
                apsKeys.append('"alert":"%s"' % alertArgument)
            elif isinstance(self.alertObject, APNSAlert):
                alertArgument = self.alertObject.build()
                apsKeys.append('"alert":{%s}' % alertArgument)

        keys.append('"aps":{%s}' % ",".join(apsKeys))

        # prepare properties
        for property in self.properties:
            keys.append(property.build())

        payload = "{%s}" % ",".join(keys)

        if len(payload) > self.maxPayloadLength:
            raise APNSPayloadLengthError("Length of Payload more "\
                                    "than %d bytes." % self.maxPayloadLength)

        return payload

    def write(self, connection=None):
        if connection == None:
            raise Exception

        n = connection.write(self.packedPayload[self.n_written:])
        if n > 0:
            self.n_written += n
            if self.n_written == self.msg_len:
                self.sent = True
        return n

    def payload(self, wrapper_id=0):
        """Build payload via struct module"""
        if self.deviceToken == None:
            raise APNSUndefinedDeviceToken("You forget to set deviceToken "\
                                            "in your notification.")

        payload = self.build()
        payloadLength = len(payload)
        tokenLength = len(self.deviceToken)
        self.wrapper_id = wrapper_id
        self.identifier = self.wrapper_id

        if self.command == 0:
            apnsPackFormat = "!BH" + str(tokenLength) + "sH" + str(payloadLength) + "s"
            self.packedPayload = struct.pack(apnsPackFormat,
                                             self.command,
                                             tokenLength,
                                             self.deviceToken,
                                             payloadLength,
                                             payload)
            self.msg_len = len(self.packedPayload)
        elif self.command == 1:
            apnsPackFormat = "!BLLH" + str(tokenLength) + "sH" +  str(payloadLength) + "s"
            self.packedPayload = struct.pack(apnsPackFormat,
                                             self.command,
                                             self.identifier,
                                             self.expiry,
                                             tokenLength,
                                             self.deviceToken,
                                             payloadLength,
                                             payload)
            self.msg_len = len(self.packedPayload)
        else:
            # TODO: Raise an appropriate exception
            raise Exception
        return self
