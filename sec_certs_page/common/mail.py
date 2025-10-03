from email.encoders import encode_base64

from flask_mail import Message as FlaskMessage


class Message(FlaskMessage):
    def _mimetext(self, text, subtype="plain"):
        res = super()._mimetext(text, subtype)
        if subtype == "html":
            del res["Content-Transfer-Encoding"]
            encode_base64(res)
        return res
