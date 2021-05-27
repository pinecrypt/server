
import click
import smtplib
from pinecrypt.server import const
from pinecrypt.server.user import User
from markdown import markdown
from jinja2 import Environment, PackageLoader
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.header import Header

env = Environment(loader=PackageLoader("pinecrypt.server", "templates/mail"))

assert env.get_template("test.md")


def send(template, to=None, attachments=(), **context):
    recipients = ()
    if to:
        recipients = (to,) + recipients
    if const.AUDIT_EMAIL:
        recipients += (const.AUDIT_EMAIL,)

    click.echo("Sending e-mail %s to %s" % (template, recipients))

    subject, text = env.get_template(template).render(context).split("\n\n", 1)
    html = markdown(text)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(subject)
    msg["From"] = Header(const.SMTP_SENDER_NAME)
    msg["From"].append("<%s>" % const.SMTP_SENDER_ADDR)

    if recipients:
        msg["To"] = Header()
        for user in recipients:
            if isinstance(user, User):
                full_name, user = user.format()
                if full_name:
                    msg["To"].append(full_name)
            msg["To"].append(user)
            msg["To"].append(", ")

    part1 = MIMEText(text, "plain", "utf-8")
    part2 = MIMEText(html, "html", "utf-8")

    msg.attach(part1)
    msg.attach(part2)

    for attachment, content_type, suggested_filename in attachments:
        part = MIMEBase(*content_type.split("/"))
        part.add_header("Content-Disposition", "attachment", filename=suggested_filename)
        part.set_payload(attachment)
        msg.attach(part)

    click.echo("Sending %s to %s" % (template, msg["to"]))
    cls = smtplib.SMTP_SSL if const.SMTP_TLS == "tls" else smtplib.SMTP
    conn = cls(const.SMTP_HOST, const.SMTP_PORT)
    if const.SMTP_TLS == "starttls":
        conn.starttls()
    if const.SMTP_USERNAME and const.SMTP_PASSWORD:
        conn.login(const.SMTP_USERNAME, const.SMTP_PASSWORD)
    conn.sendmail(const.SMTP_SENDER_ADDR, [u.mail if isinstance(u, User) else u for u in recipients], msg.as_string())

