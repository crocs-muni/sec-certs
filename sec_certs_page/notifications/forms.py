from flask_wtf import FlaskForm
from wtforms import BooleanField, FieldList, FormField, HiddenField, SelectField, StringField, validators
from wtforms.widgets import TableWidget


class ChangeSubscriptionForm(FlaskForm):
    subscribe = BooleanField("Subscribe", [])
    certificate_type = HiddenField("Certificate Type", [validators.DataRequired()])
    certificate_hashid = HiddenField("Certificate ID", [validators.DataRequired()])
    updates = SelectField(
        "Updates",
        [validators.DataRequired()],
        choices=[("all", "All updates"), ("vuln", "Vulnerability information only")],
    )


class NewCertificateSubscriptionForm(FlaskForm):
    subscribe = BooleanField("Subscribe", [])
    which = StringField(
        "Which",
        [validators.DataRequired(), validators.AnyOf(["fips", "cc", "pp"])],
        render_kw={"readonly": True},
    )


class ManageForm(FlaskForm):
    changes = FieldList(FormField(ChangeSubscriptionForm), widget=TableWidget())
    new = FieldList(FormField(NewCertificateSubscriptionForm), widget=TableWidget())
