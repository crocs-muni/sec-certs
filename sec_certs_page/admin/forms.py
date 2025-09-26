from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, SelectField, StringField, validators


class ConfigEditForm(FlaskForm):
    key = StringField("key", [validators.DataRequired()])
    value = StringField("value")
    type = SelectField(
        "type",
        [validators.DataRequired()],
        choices=[("string", "String"), ("int", "Int"), ("float", "Float"), ("boolean", "Boolean")],
        default="string",
    )
