from flask import Flask, abort, flash, request, session, redirect, url_for
from flask import render_template_string, render_template
from flask_github import GitHub, GitHubError
from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, HiddenField, validators
from itsdangerous import URLSafeTimedSerializer

from datetime import datetime
import os
import pprint
import requests
import stripe
import logging

SECRET_KEY = 'development key'
DEBUG = True

# Set these values
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
MAILGUN_SANDBOX = os.environ.get('MAILGUN_SANDBOX')
MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY')
SLACK_URL = os.environ.get('SLACK_URL')

# "osmus" Organization, "Board" Team
TEAM_ID = os.environ.get('GITHUB_TEAM_ID')

# setup flask
app = Flask(__name__)
app.config.from_object(__name__)

# setup github-flask
github = GitHub(app)

stripe.api_key = app.config.get('STRIPE_SECRET_KEY')


def tell_slack(message):
    return requests.post(SLACK_URL, json={'text': message})


def send_email(recipient, subject, html):
    app.logger.info("Sending an email to %s", recipient)
    request_url = 'https://api.mailgun.net/v2/{0}/messages'.format(app.config['MAILGUN_SANDBOX'])
    response = requests.post(request_url, auth=('api', app.config['MAILGUN_API_KEY']), data={
        'from': 'ian@openstreetmap.us',
        'to': recipient,
        'subject': subject,
        'html': html
    })
    response.raise_for_status()


class RequestMemberUpdateLinkForm(FlaskForm):
    email = StringField('Email Address', [validators.Length(min=6, max=35)])


class MemberUpdateForm(FlaskForm):
    first_name = StringField('First Name', [validators.DataRequired()])
    last_name = StringField('Last Name', [validators.DataRequired()])
    osm_username = StringField('OSM Username', [validators.Length(min=3, max=255), validators.Optional()])
    email = StringField('Email Address', [validators.Email()])
    address1 = StringField('Street Address')
    address2 = StringField('Address Line 2')
    city = StringField('City')
    region = StringField('State / Region / Province')
    postal_code = StringField('Postal / Zip Code')
    country = StringField('Country')
    phone = StringField('Phone Number')


@app.before_first_request
def setup_logging():
    if not app.debug:
        # In production mode, add log handler to sys.stderr.
        app.logger.addHandler(logging.StreamHandler())
        app.logger.setLevel(logging.INFO)


@github.access_token_getter
def token_getter():
    return session.get('github_access_token')


@app.route('/github-callback')
@github.authorized_handler
def authorized(access_token):
    next_url = request.args.get('next') or url_for('member_list')
    if access_token is None:
        return redirect(next_url)

    session['github_access_token'] = access_token

    # Check to make sure the user is a member of the required team
    user = github.get('user')
    user_login = user.get('login')
    try:
        membership = github.get('teams/{}/members/{}'.format(TEAM_ID, user_login))
        session['github_login'] = user_login
        return redirect(next_url)
    except GitHubError:
        flash('Could not log you in', 'error')
        return redirect(url_for('logout'))


@app.template_filter('relative_timestamp')
def _relative_timestamp_filter(timestamp):
    return datetime.fromtimestamp(timestamp).isoformat()


@app.route('/membership', methods=['GET', 'POST'])
def request_membership():
    form = RequestMemberUpdateLinkForm()
    if form.validate_on_submit():
        email = form.email.data

        ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

        customer_iter = stripe.Customer.auto_paging_iter(limit=50)
        for customer in customer_iter:
            if customer.email and customer.email.lower() == email.lower():
                app.logger.info("Found email %s", email)
                subject = "Update Your OpenStreetMap US Payment Details"
                token = ts.dumps(customer.id, salt='email-confirm-key')
                confirm_url = url_for('membership_update', token=token, _external=True)
                html = render_template(
                    'email_activate.html',
                    confirm_url=confirm_url
                )
                send_email(customer.email, subject, html)
                break

        flash('Check your email for a link to update your membership details')
        return redirect(url_for('request_membership'))

    return render_template('membership_update_request.html', form=form)


@app.route('/membership/<string:token>', methods=['GET', 'POST'])
def membership_update(token):
    try:
        ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        customer_id = ts.loads(token, salt="email-confirm-key", max_age=86400)
    except:
        abort(404)

    customer = stripe.Customer.retrieve(customer_id, expand=['default_source'])
    app.logger.info("Got a valid customer! %s", customer.id)

    form = MemberUpdateForm()
    if form.validate_on_submit():
        customer.metadata['first_name'] = form.first_name.data
        customer.metadata['last_name'] = form.last_name.data
        customer.metadata['osm_username'] = form.osm_username.data
        customer.shipping = {
            'name': ' '.join([form.first_name.data, form.last_name.data]),
            'phone': form.phone.data or None,
            'address': {
                'line1': form.address1.data or None,
                'line2': form.address2.data or None,
                'city': form.city.data or None,
                'state': form.region.data or None,
                'postal_code': form.postal_code.data or None,
                'country': form.country.data or None,
            }
        }
        customer.save()

        flash('Your details have been updated, thanks!')
        return redirect(url_for('membership_update', token=token))
    else:

        form.email.data = customer.email
        form.osm_username.data = customer.metadata.get('osm_username')
        form.first_name.data = customer.metadata.get('first_name')
        form.last_name.data = customer.metadata.get('last_name')
        if customer.shipping:
            form.address1.data = customer.shipping.address.line1
            form.address2.data = customer.shipping.address.line2
            form.city.data = customer.shipping.address.city
            form.region.data = customer.shipping.address.state
            form.postal_code.data = customer.shipping.address.postal_code
            form.country.data = customer.shipping.address.country
            form.phone.data = customer.shipping.phone

    pprint.pprint(customer.default_source)
    return render_template(
        'membership_update.html',
        form=form,
        token=token,
        customer_email=customer.email,
        current_payment=customer.default_source,
        stripe_key=app.config['STRIPE_PUBLISHABLE_KEY'],
    )


@app.route('/membership/<string:token>/payment', methods=['POST'])
def membership_payment_update(token):
    try:
        ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        customer_id = ts.loads(token, salt="email-confirm-key", max_age=86400)
    except:
        abort(404)

    customer = stripe.Customer.retrieve(customer_id)
    customer.source = request.form['stripeToken']
    customer.save()

    flash('Your credit card details have been updated.')

    return redirect(url_for('membership_update', token=token))


@app.route('/members')
def member_list():
    if session.get('github_access_token') is None:
        return render_template('login.html')

    after = request.args.get('after')
    before = request.args.get('before')
    customers = stripe.Customer.list(
        limit=25,
        starting_after=after,
        ending_before=before,
        include=['total_count']
    )

    return render_template('members.html', customers=customers)


@app.route('/members/<string:customer_id>')
def show_member(customer_id):
    if session.get('github_access_token') is None:
        return redirect(url_for('member_list'))

    customer = stripe.Customer.retrieve(customer_id)

    return render_template('show_member.html', customer=customer)


@app.route('/webhooks/stripe', methods=["POST"])
def stripe_webhook():
    webhook_data = request.get_json()
    event = stripe.Event.retrieve(webhook_data['id'])
    app.logger.info("Received Stripe webhook event: {}".format(event))

    if event.type == 'invoice.payment_failed':
        customer = stripe.Customer.retrieve(event.data.object.customer)
        email = customer.email
        app.logger.info("Invoice payment failed for customer: {}".format(customer))
        tell_slack(":rotating_light: {email}'s automatic membership renewal failed. I'm emailing them to remind them about it.".format(email=email))


    return "ok"


@app.route('/members/login')
def github_login():
    if session.get('github_access_token', None) is None:
        return github.authorize()
    else:
        return 'Already logged in'


@app.route('/members/logout')
def github_logout():
    session.pop('github_access_token', None)
    session.pop('github_login', None)
    return redirect(url_for('member_list'))


if __name__ == '__main__':
    app.run(debug=True)
