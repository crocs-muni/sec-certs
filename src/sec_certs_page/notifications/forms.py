from flask_wtf import FlaskForm
from wtforms import BooleanField, FieldList, FormField, HiddenField, SelectField, StringField, validators
from wtforms.widgets import TableWidget


class SubscriptionForm(FlaskForm):
    subscribe = BooleanField("Subscribe", [])
    certificate_hashid = HiddenField("Certificate ID", [validators.DataRequired()])
    updates = SelectField(
        "Updates",
        [validators.DataRequired()],
        choices=[("vuln", "Vulnerability information only"), ("all", "All updates")],
    )


class ManageForm(FlaskForm):
    certificates = FieldList(FormField(SubscriptionForm), widget=TableWidget())


class UnsubscribeForm(FlaskForm):
    email = StringField("email", [validators.DataRequired(), validators.Email()])
