import sys
import os
import smtplib
import mimetypes
from email import encoders
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import formatdate


def attach_file(msg, filepath):
    filename = os.path.basename(filepath)
    ctype, encoding = mimetypes.guess_type(filepath)
    if ctype is None or encoding is not None:
        ctype = 'application/octet-stream'
    maintype, subtype = ctype.split('/', 1)
    if maintype == 'text':
        with open(filepath) as fp:
            file = MIMEText(fp.read(), _subtype=subtype)
            fp.close()
    else:
        with open(filepath, 'rb') as fp:
            file = MIMEBase(maintype, subtype)
            file.set_payload(fp.read())
            fp.close()
            encoders.encode_base64(file)
    file.add_header('Content-Disposition', 'attachment', filename=filename)
    msg.attach(file)


def send_mail(body_text, host, getter, from_addr, user, psw, file_name=None):
    print("sending log mail to:", getter)
    try:
        host = host
        from_addr = from_addr

        to_email = getter

        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["Subject"] = "TC report"
        msg["Date"] = formatdate(localtime=True)

        if body_text:
            msg.attach(MIMEText(body_text))

        to_list = []
        for el in to_email.split(";"):
            if el.strip() != "":
                to_list.append(el.strip())

        msg["To"] = ', '.join(to_list)

        if file_name:
            if os.path.isfile(file_name):
                attach_file(msg, file_name)

        emails = to_list
        server = smtplib.SMTP(host)
        server.login(user, psw)
        server.sendmail(user, emails, msg.as_string())
        server.quit()
    except BaseException as ex:
        sys.stderr.write("EXCEPTION: " + str(ex) + "\n")
        raise ex
