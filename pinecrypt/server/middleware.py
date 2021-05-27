import ipaddress
import socket
import time
from user_agents import parse
from prometheus_client import Counter, Histogram, generate_latest

class NormalizeMiddleware(object):
    def __init__(self):

        self.requests = Counter(
            "http_total_request",
            "Counter of total HTTP requests",
            ["method", "path", "status"])

        self.request_historygram = Histogram(
            "request_latency_seconds",
            "Histogram of request latency",
            ["method", "path", "status"])

    def process_request(self, req, resp, *args):
        req.context["remote"] = {
            "addr": ipaddress.ip_address(req.access_route[0]),
        }

        if req.user_agent:
            req.context["remote"]["user_agent"] = parse(req.user_agent)

        # TODO: This is potentially dangerous and should be toggleable
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(str(req.context["remote"]["addr"]))
        except (socket.herror, OSError): # Failed to resolve hostname or resolved to multiple
            pass
        else:
            req.context["remote"]["hostname"] = hostname
        req.start_time = time.time()


    def process_response(self, req, resp, resource, req_succeeded):
        resp_time = time.time() - req.start_time
        self.requests.labels(method=req.method, path=req.path, status=resp.status).inc()
        self.request_historygram.labels(method=req.method, path=req.path, status=resp.status).observe(resp_time)

class PrometheusEndpoint(object):
    def on_get(self, req, resp):
        data = generate_latest()
        resp.content_type = "text/plain; version=0.0.4; charset=utf-8"
        resp.text = str(data.decode("utf-8"))

