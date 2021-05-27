
import click
import os
import asyncio
from sanic import Sanic
from sanic.exceptions import ServerError
from sanic.response import file_stream
from pinecrypt.server import const

app = Sanic("builder")
app.config.RESPONSE_TIMEOUT = 300

@app.route("/api/build/")
async def view_build(request):
    build_script_path = "/builder/script/mfp.sh"
    suffix = "-glinet_gl-ar150-squashfs-sysupgrade.bin"
    suggested_filename = "mfp%s" % suffix
    build = "/builder/src"
    log_path = build + "/build.log"

    proc = await asyncio.create_subprocess_exec(
        build_script_path,
        stdout=open(log_path, "w"),
        close_fds=True,
        shell=False,
        cwd=os.path.dirname(os.path.realpath(build_script_path)),
        env={
            "PROFILE": "glinet_gl-ar150",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "AUTHORITY_NAMESPACE": const.AUTHORITY_NAMESPACE,
            "BUILD": build,
            "OVERLAY": build + "/overlay/"
        },
        startupinfo=None,
        creationflags=0,
    )

    stdout, stderr = await proc.communicate()

    if proc.returncode:
        raise ServerError("Build script finished with non-zero exitcode, see %s for more information" % log_path)

    for root, dirs, files in os.walk("/builder/src/bin/targets"):
        for filename in files:
            if filename.endswith(suffix):
                path = os.path.join(root, filename)
                click.echo("Serving: %s" % path)
                return await file_stream(
                        path,
                        headers={
                           "Content-Disposition": "attachment; filename=%s" % suggested_filename
                        }
                    )
    raise ServerError("Failed to find image builder directory in %s" % build)

