from __future__ import print_function
from __future__ import absolute_import
import logging
from typing import OrderedDict
import dpkt
try:
    from collections import OrderedDict
except ImportError:
    # Python 2.6
    OrderedDict = dict
from dpkt.compat import BytesIO, iteritems
import gzip


def parse_headers(f):
    """Return dict of HTTP headers parsed from a file object."""
    d = OrderedDict()
    while 1:
        # The following logic covers two kinds of loop exit criteria.
        # 1) If the header is valid, when we reached the end of the header,
        #    f.readline() would return with '\r\n', then after strip(),
        #    we can break the loop.
        # 2) If this is a weird header, which do not ends with '\r\n',
        #    f.readline() would return with '', then after strip(),
        #    we still get an empty string, also break the loop.
        line = f.readline().strip().decode("ascii", "ignore")
        if not line:
            break
        l = line.split(':', 1)
        #         logging.info("length is {}".format(len(l[0].split())))
        if len(l[0].split()) != 1:
            raise dpkt.UnpackError('invalid header: %r' % line)
        k = l[0].lower()
        v = len(l) != 1 and l[1].lstrip() or ''
        if k in d:
            if not type(d[k]) is list:
                d[k] = [d[k]]
            d[k].append(v)
        else:
            d[k] = v
    return d


def parse_body(f, headers):
    """Return HTTP body parsed from a file object, given HTTP header dict."""
    length_chunked_gzip = {"need_length": 0, "chunked": 0, "gzip": 0}
    if headers.get('content-encoding', '').lower() == 'gzip':
        length_chunked_gzip["gzip"] = 1
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        l = []
        found_end = False
        while 1:
            try:
                sz = f.readline().split(None, 1)[0]
            except IndexError:
                length_chunked_gzip["chunked"] = 1
                body = b''
                return body, length_chunked_gzip
            if length_chunked_gzip["gzip"] == 0:
                n = int(sz, 16)
                if n == 0:
                    found_end = True
                buf = f.read(n)
                if f.readline().strip():
                    break
                if n and len(buf) == n:
                    l.append(buf)
                else:
                    break
            else:
                try:
                    buf = f.read()
                    body = gzip.decompress(buf)
                except:
                    body = buf
                    pass

        if not found_end:
            body = b''.join(l)
            return body, length_chunked_gzip
        body = b''.join(l)
    elif 'content-length' in headers:
        n = int(headers['content-length'])
        body = f.read(n)
        if len(body) != n:
            length_chunked_gzip["need_length"] = n - len(body)
            if length_chunked_gzip["gzip"] == 1:
                try:
                    body = gzip.decompress(body)
                except:
                    pass
            return body, length_chunked_gzip
        else:
            length_chunked_gzip["need_length"] = 0
            if length_chunked_gzip["gzip"] == 1:
                try:
                    body = gzip.decompress(body)
                except:
                    pass
            return body, length_chunked_gzip


    elif 'content-type' in headers:
        if length_chunked_gzip["gzip"] == 0:
            body = f.read()
        else:
            try:
                buf = f.read()
                body = gzip.decompress(buf)
            except:
                pass
    else:
        body = b''
    return body, length_chunked_gzip


class Message(dpkt.Packet):
    """Hypertext Transfer Protocol headers + body.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of HTTP.
        TODO.
    """

    __metaclass__ = type
    __hdr_defaults__ = {}
    headers = None
    body = None
    length_chunked_gzip = {"need_length": 0, "chunked": 0, "gzip": 0}

    def __init__(self, *args, **kwargs):
        if args:
            self.unpack(args[0])
        else:
            self.headers = OrderedDict()
            self.body = b''
            self.data = b''
            self.length_chunked_gzip = {
                "need_length": 0,
                "chunked": 0,
                "gzip": 0
            }
            # NOTE: changing this to iteritems breaks py3 compatibility
            for k, v in self.__hdr_defaults__.items():
                setattr(self, k, v)
            for k, v in iteritems(kwargs):
                setattr(self, k, v)

    def unpack(self, buf, is_body_allowed=True):
        f = BytesIO(buf)
        # Parse headers
        self.headers = parse_headers(f)
        # Parse body
        #         logging.info(is_body_allowed)
        if is_body_allowed:
            self.body, self.length_chunked_gzip = parse_body(f, self.headers)
        else:
            self.body = b''
            self.length_chunked_gzip = {
                "need_length": 0,
                "chunked": 0,
                "gzip": 0
            }
        # Save the rest
        self.data = f.read()

    def pack_hdr(self):
        return ''.join(['%s: %s\r\n' % t for t in iteritems(self.headers)])

    def __needlen__(self):
        return self.length_chunked_gzip

    def __len__(self):
        return len(str(self))

    def __str__(self):
        return '%s\r\n%s' % (self.pack_hdr(), self.body.decode(
            "utf8", "ignore"))

    def __bytes__(self):
        return self.pack_hdr().encode("ascii", "ignore") + b'\r\n' + (self.body
                                                                      or b'')


class Request(Message):
    """Hypertext Transfer Protocol Request.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of HTTP request.
        TODO.
    """

    __hdr_defaults__ = {
        'method': 'GET',
        'uri': '/',
        'version': '1.0',
    }
    __methods = dict.fromkeys(
        ('GET', 'PUT', 'ICY', 'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
         'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE', 'DELETE',
         'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY', 'BDELETE',
         'CONNECT', 'OPTIONS', 'CHECKIN', 'PROPFIND', 'CHECKOUT', 'CCM_POST',
         'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND', 'BPROPPATCH', 'UNCHECKOUT',
         'MKACTIVITY', 'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
         'VERSION-CONTROL', 'BASELINE-CONTROL'))
    __proto = 'HTTP'
    length_chunked_gzip = {"need_length": 0, "chunked": 0, "gzip": 0}

    def unpack(self, buf):
        f = BytesIO(buf)
        line = f.readline().decode("ascii", "ignore")
        l = line.strip().split()
        if len(l) < 2:
            raise dpkt.UnpackError('invalid request: %r' % line)
        if l[0] not in self.__methods:
            raise dpkt.UnpackError('invalid http method: %r' % l[0])
        if len(l) == 2:
            # HTTP/0.9 does not specify a version in the request line
            self.version = '0.9'
        else:
            if not l[2].startswith(self.__proto):
                raise dpkt.UnpackError('invalid http version: %r' % l[2])
            self.version = l[2][len(self.__proto) + 1:]
        self.method = l[0]
        self.uri = l[1]
        Message.unpack(self, f.read())
        self.length_chunked_gzip = Message.__needlen__(self)

    def __str__(self):
        return '%s %s %s/%s\r\n' % (self.method, self.uri, self.__proto,
                                    self.version) + Message.__str__(self)

    def __bytes__(self):
        str_out = '%s %s %s/%s\r\n' % (self.method, self.uri, self.__proto,
                                       self.version)
        return str_out.encode("ascii", "ignore") + Message.__bytes__(self)


class Response(Message):
    """Hypertext Transfer Protocol Response.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of HTTP Response.
        TODO.
    """

    __hdr_defaults__ = {'version': '1.0', 'status': '200', 'reason': 'OK'}
    __proto = 'HTTP'
    length_chunked_gzip = {"need_length": 0, "chunked": 0, "gzip": 0}

    def unpack(self, buf):
        f = BytesIO(buf)
        line = f.readline()
        l = line.strip().decode("ascii", "ignore").split(None, 2)
        if len(l) < 2 or not l[0].startswith(
                self.__proto) or not l[1].isdigit():
            raise dpkt.UnpackError('invalid response: %r' % line)
        self.version = l[0][len(self.__proto) + 1:]
        self.status = l[1]
        self.reason = l[2] if len(l) > 2 else ''
        # RFC Sec 4.3.
        # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3.
        # For response messages, whether or not a message-body is included with
        # a message is dependent on both the request method and the response
        # status code (section 6.1.1). All responses to the HEAD request method
        # MUST NOT include a message-body, even though the presence of entity-
        # header fields might lead one to believe they do. All 1xx
        # (informational), 204 (no content), and 304 (not modified) responses
        # MUST NOT include a message-body. All other responses do include a
        # message-body, although it MAY be of zero length.
        is_body_allowed = int(self.status) >= 200 and 204 != int(
            self.status) != 304
        Message.unpack(self, f.read(), is_body_allowed)
        self.length_chunked_gzip = Message.__needlen__(self)

    def __str__(self):
        return '%s/%s %s %s\r\n' % (self.__proto, self.version, self.status,
                                    self.reason) + Message.__str__(self)

    def __bytes__(self):
        str_out = '%s/%s %s %s\r\n' % (self.__proto, self.version, self.status,
                                       self.reason)
        return str_out.encode("ascii", "ignore") + Message.__bytes__(self)
