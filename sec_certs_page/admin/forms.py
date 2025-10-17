from flask_wtf import FlaskForm
from wtforms import SelectField, SelectMultipleField, StringField, validators


class ConfigEditForm(FlaskForm):
    key = StringField("key", [validators.DataRequired()])
    value = StringField("value")
    type = SelectField(
        "type",
        [validators.DataRequired()],
        choices=[("string", "String"), ("int", "Int"), ("float", "Float"), ("boolean", "Boolean")],
        default="string",
    )


class UserEditForm(FlaskForm):
    # roles will be a comma-separated list rendered as multi-select in template
    roles = SelectMultipleField("Roles", choices=[], coerce=str, validators=[])
