import logging
import os
from pinecrypt.server import authority, const
from jinja2 import Environment, FileSystemLoader
from .utils.firewall import whitelist_subject
from pinecrypt.server.mongolog import LogHandler

env = Environment(loader=FileSystemLoader(const.SCRIPT_DIR), trim_blocks=True)
logger = LogHandler()

class ScriptResource(object):
    @whitelist_subject
    def on_get(self, req, resp, id):
        path, buf, cert, attribs = authority.get_attributes(id)
        # TODO: are keys unique?
        named_tags = {}
        other_tags = []
        cn = cert["common_name"]

        script = named_tags.get("script", "default.sh")
        assert script in os.listdir(const.SCRIPT_DIR)
        resp.set_header("Content-Type", "text/x-shellscript")
        resp.body = env.get_template(os.path.join(script)).render(
            authority_name=const.FQDN,
            common_name=cn,
            other_tags=other_tags,
            named_tags=named_tags,
            attributes=attribs.get("user").get("machine"))
        logger.info("Served script %s for %s at %s" % (script, cn, req.context["remote"]["addr"]))
        # TODO: Assert time is within reasonable range
