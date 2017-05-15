#!/usr/bin/python
"""Transparent REST proxy"""


import argparse
import json
import paramiko
import sys
import time

from botocore import session as aws_session

from twisted.internet import reactor, protocol
from twisted.python import log
from twisted.web import http
from twisted.web.resource import Resource
from twisted.web.server import Site, NOT_DONE_YET

import botocore.session
from oslo_config import types


class AWSClient:
    def __init__(self, access, secret, url, region, ca_bundle=None, client_name='ec2'):
        connection_data = {
            'config_file': (None, 'AWS_CONFIG_FILE', None, None),
            'region': ('region', 'AWS_DEFAULT_REGION', region, None),
        }
        session = aws_session.get_session(connection_data)
        kwargs = {
            'region_name': region,
            'endpoint_url': url,
            'aws_access_key_id': access,
            'aws_secret_access_key': secret
        }
        if ca_bundle:
            try:
                kwargs['verify'] = types.Boolean()(ca_bundle)
            except Exception:
                kwargs['verify'] = ca_bundle
        self._client = session.create_client(client_name, **kwargs)

    def allocate_floating_ip(self):
        response = self._client.allocate_address(
            Domain='vpc',
        )
        return response


class SSHClient:
    RETRY = 3
    RETRY_DELAY = 2

    def __init(self, host, key_file_name=None):
        self._host = host
        self._key_file_name = key_file_name
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def execute(self, commands=[]):
        err_count = 0
        while True:
            try:
                self._client.connect(hostname=self._host, key_filename=self._key_file_name)
                for i in commands:
                    log.msg("SSHCommand: execute '%s'" % i)
                    _, stdout, stderr = self._client.exec_command(i)
                    output = stderr.readlines() + stdout.readlines()
                    log.msg("SSHCommand: output: %s" % output)
                break;
            except paramiko.AuthenticationException:
                log.err('SSHCommand: Authentication failed when connecting to %s' % self._host)
                raise
            except:
                log.err("Could not SSH to %s, waiting for it to start" % host_ip)
                err_count += 1
                time.sleep(self.RETRY_DELAY)
            finally:
                self._client.close()

            if err_count > self.RETRY:
                log.err("SSHCommand: No more retries.. raise SSHException")
                raise paramiko.SSHException('SSHCommand: Failed to execute "%s" on host %s' % (self._cmd, self._host))


class IPTablesRule:
    pass


class ProxyClient(http.HTTPClient):
    def __init__(self, method, uri, data, headers, original_request):
        self.method = method
        self.uri = uri
        self.post_data = data
        self.headers = headers
        self.original_request = original_request
        self.content_length = None

    def sendRequest(self):
        log.msg("ProxyClient: sendRequest: %s %s" % (self.method, self.uri))
        self.sendCommand(self.method, self.uri)

    def sendHeaders(self):
        for key, values in self.headers:
            if key.lower() == 'connection':
                values = ['close']
            elif key.lower() == 'keep-alive':
                next

            for value in values:
                log.msg("ProxyClient: sendHeader: %s=%s" % (key, value))
                self.sendHeader(key, value)
        self.endHeaders()

    def sendPostData(self):
        log.msg("ProxyClient: sendPostData: %s" % (self.post_data))
        # if self.method == 'POST':
        if self.post_data is not None and len(self.post_data) > 0:
            self.transport.write(self.post_data)

    def connectionMade(self):
        log.msg("ProxyClient: connectionMade")
        self.sendRequest()
        self.sendHeaders()
        self.sendPostData()

    def handleStatus(self, version, code, message):
        log.msg("ProxyClient: handleStatus: %s %s %s" % (version, code, message))
        self.original_request.setResponseCode(int(code), message)

    def handleHeader(self, key, value):
        log.msg("ProxyClient: handleHeader: %s=%s" % (key, value))
        if key.lower() == 'content-length':
            self.content_length = value
        else:
            self.original_request.responseHeaders.addRawHeader(key, value)

    def handleResponse(self, data):
        log.msg("ProxyClient: handleResponse: %s" % (data, ))
        if self.content_length != None:
            self.original_request.setHeader('Content-Length', len(data))
        self.original_request.write(data)
        self.original_request.finish()
        self.transport.loseConnection()


class ProxyClientFactory(protocol.ClientFactory):
    protocol = ProxyClient

    def __init__(self, method, uri, data, headers, original_request):
        # self.protocol = ProxyClient
        self.method = method
        self.uri = uri
        self.post_data = data
        self.headers = headers
        self.original_request = original_request

    def buildProtocol(self, addr):
        log.msg("ProxyClientFactory: buildProtocol: method=%s, uri=%s, data=%s, headers=%s"
                % (self.method, self.uri, self.post_data, self.headers))
        return self.protocol(self.method, self.uri, self.post_data,
                             self.headers, self.original_request)

    def clientConnectionFailed(self, connector, reason):
        log.err("ProxyClientFactory: Server connection failed: %s" % reason)
        self.originalRequest.setResponseCode(504)
        self.originalRequest.finish()


# class ProxyRequest(http.Request):
#     options = None
#
#     def __init__(self, channel, queued, reactor=reactor):
#         http.Request.__init__(self, channel, queued)
#         self.reactor = reactor
#
#     def process(self):
#         host = self.options.dst_address
#         port = self.options.dst_port
#         log.msg("ProxyRequest: process: host=%s, port=%s" % (host, port))
#         self.setHost(host.encode('utf-8'), port)
#         self.content.seek(0, 0)
#         request_data = self.content.read()
#         client_factory = ProxyClientFactory(self.method, self.uri, request_data,
#                                             self.requestHeaders.getAllRawHeaders(),
#                                             self)
#         self.reactor.connectTCP(host, port, client_factory)
#
#         log.msg("ProxyRequest: process: end")
#
#
# class TransparentProxy(http.HTTPChannel):
#     requestFactory = ProxyRequest
#
#
# class ProxyFactory(http.HTTPFactory):
#     protocol = TransparentProxy


class ProxyResource(Resource):
    options = None
    isLeaf = False

    def __init__(self):
        Resource.__init__(self)
        self.host = None
        self.port = None
        self.reactor = reactor
        self.request = None
        self.request_data = None

    def getChild(self, path, request):
        if len(path) == 0:
            return self
        return Resource.getChild(self, path, request)

    def render(self, request):
        self.request = request
        self._prepare()
        self._customize()
        self._proxy()
        return NOT_DONE_YET

    def _prepare(self):
        self.host = self.options.dst_address
        self.port = self.options.dst_port
        self.request.setHost(self.host.encode('utf-8'), self.port)
        self.request.content.seek(0, 0)
        self.request_data = self.request.content.read()

    def _proxy(self):
        client_factory = ProxyClientFactory(self.request.method, self.request.uri, self.request_data,
                                            self.request.requestHeaders.getAllRawHeaders(),
                                            self.request)
        self.reactor.connectTCP(self.host, self.port, client_factory)

    def _customize(self):
        pass


class FIPResource(ProxyResource):
    def __init__(self):
        ProxyResource.__init__(self)
        self._ec2_client = None

    def _allocate_floating_ip(self):
        log.msg('Allocate floating IP on AWS...')
        if self._ec2_client is None:
            opts = self.options
            self._ec2_client = AWSClient(
                access=opts.aws_access_key_id,
                secret=opts.aws_secret_key,
                url=opts.aws_endpoint,
                region=opts.aws_region)
        response = self._ec2_client.allocate_floating_ip()
        log.msg('Allocate floating IP on AWS response: %s' % response)
        return response['PublicIp']

    def _customize(self):
        decoded_request_data = json.load(self.request_data.decode('utf-8'))
        ctx = decoded_request_data.get('context', None)
        data = decoded_request_data.get('data', None)
        res = data.get('resource', None)
        if ctx is None or data is None or res is None:
            return
        res_type = ctx.get('type', None)
        if res_type != 'floatingip':
            self._customize_fip(ctx, res)
        self.request_data = json.dumps(decoded_request_data).encode('utf-8')

    def _customize_fip(self, ctx, res):
        if ctx.get('operation', None) == 'CREATE':
            self._customize_fip_create(res)
        elif ctx.get('operation', None) == 'UPDATE':
            self._customize_fip_update(res)

    def _customize_fip_create(self, res):
        fip = res.get('floating_ip_address', None)
        if fip is None or len(fip) == 0:
            fip = self._allocate_floating_ip()
            res['floating_ip_address'] = fip

    def _customize_fip_update(self, res):
        port_id = res.get('port_id', None)
        if port_id is not None and len(port_id) > 0:
            self._customize_fip_associate(res)
        else:
            self._customize_fip_disassociate(res)

    def _customize_fip_associate(self, res):
        pass

    def _customize_fip_disassociate(self, res):
        pass


class ProxySite(Site):
    def __init__(self, *args, **kwargs):
        Site.__init__(self, *args, **kwargs)


def parse_opts():
    parser = argparse.ArgumentParser()
    parser.add_argument('--src_address', type=str, default='127.0.0.1',
                        help='Source address to listen')
    parser.add_argument('--src_port', type=int, default=8082,
                        help='Source port')
    parser.add_argument('--dst_address', type=str, default='127.0.0.1',
                        help='Destination address')
    parser.add_argument('--dst_port', type=int, default=8082,
                        help='Destination port')
    parser.add_argument('--aws_endpoint', type=str, default='https://ec2.amazonaws.com',
                        help='AWS endpoint')
    parser.add_argument('--aws_access_key_id', type=str,
                        help='AWS Access Key ID')
    parser.add_argument('--aws_secret_key', type=str,
                        help='AWS Secret Key')
    parser.add_argument('--aws_region', type=str,
                        help='AWS Region')

    return parser.parse_args()


def get_proxy_factory(options):
    # ProxyRequest.options = options
    # return ProxyFactory()
    ProxyResource.options = options
    root_resource = ProxyResource()
    root_resource.putChild(b'/neutron/floatingip', FIPResource())
    return ProxySite(root_resource)


def main():
    options = parse_opts()

    log.startLogging(sys.stdout)

    reactor.listenTCP(options.src_port, get_proxy_factory(options), interface=options.src_address)
    reactor.run()


if __name__ == "__main__":
    main()