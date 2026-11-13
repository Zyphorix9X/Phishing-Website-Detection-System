import re
import unicodedata

from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Optional, ValidationError

from phishing_app.validation import URLValidationError, normalize_url


def valid_email(form, field):
    value = (field.data or "").strip()
    if value.count('@') != 1:
        raise ValidationError("Enter a valid email address.")
    local, domain = value.rsplit('@', 1)
    try:
        domain = domain.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValidationError("Enter a valid email address.")
    atom = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    labels = domain.split('.')
    if (len(local) > 64 or len(local) + 1 + len(domain) > 254 or len(domain) > 253
        or not re.fullmatch(atom + r"(?:\." + atom + r")*", local)
        or len(labels) < 2 or labels[-1].isdigit()
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
        raise ValidationError("Enter a valid email address, such as name@example.com.")
    field.data = local.lower() + '@' + domain


def valid_full_name(form, field):
    value = field.data or ''
    if any(unicodedata.category(char).startswith('C') for char in value):
        raise ValidationError("Your name contains an unsupported character.")
    value = ' '.join(value.split())
    if not 2 <= len(value) <= 120 or not any(char.isalpha() for char in value):
        raise ValidationError("Enter a name between 2 and 120 characters.")
    if any(not (char.isalpha() or unicodedata.category(char).startswith('M') or char in " '-.’") for char in value):
        raise ValidationError("Use letters, spaces, apostrophes, hyphens, or periods in your name.")
    field.data = value


def strong_password(form, field):
    value = field.data or ""
    if len(value) > 256:
        raise ValidationError("Passwords must be 256 characters or fewer.")
    if len(value) < 12 or not any(c.islower() for c in value) or not any(c.isupper() for c in value) or not any(c.isdigit() for c in value) or not any(not c.isalnum() and not c.isspace() for c in value):
        raise ValidationError("Use at least 12 characters with upper and lower case letters, a number, and a symbol.")


def valid_url(form, field):
    try:
        normalize_url(field.data or "")
    except URLValidationError as exc:
        raise ValidationError(str(exc)) from exc


class RegistrationForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), valid_full_name])
    email = StringField("Email address", validators=[DataRequired(), valid_email])
    password = PasswordField("Password", validators=[DataRequired(), strong_password])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", message="Passwords do not match.")])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField("Email address", validators=[DataRequired(), valid_email])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign in")


class ScanForm(FlaskForm):
    url = StringField("URL to analyze", validators=[DataRequired(), Length(max=2048), valid_url])
    submit = SubmitField("Analyze URL")


class AccountForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), valid_full_name])
    email = StringField("Email address", validators=[DataRequired(), valid_email])
    current_password = PasswordField("Current password", validators=[Length(max=256)])
    new_password = PasswordField("New password", validators=[Optional(), strong_password])
    confirm_password = PasswordField("Confirm new password", validators=[EqualTo("new_password", message="Passwords do not match.")])
    submit = SubmitField("Save changes")
