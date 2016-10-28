from flask import Flask, flash, request, session, redirect, url_for
from flask import render_template_string, render_template
from flask_github import GitHub, GitHubError
from datetime import datetime
import os
import pprint
import stripe

SECRET_KEY = 'development key'
DEBUG = True

# Set these values
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')

# "osmus" Organization, "Board" Team
TEAM_ID = os.environ.get('GITHUB_TEAM_ID')

# setup flask
app = Flask(__name__)
app.config.from_object(__name__)

# setup github-flask
github = GitHub(app)

stripe.api_key = app.config.get('STRIPE_SECRET_KEY')

@github.access_token_getter
def token_getter():
    return session.get('github_access_token')


@app.route('/github-callback')
@github.authorized_handler
def authorized(access_token):
    next_url = request.args.get('next') or url_for('index')
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


@app.route('/')
def index():
    if session.get('github_access_token'):
        t = """Hello {{ session.get("github_login") }}!
            <a href="{{ url_for("logout") }}">Logout</a>
            <a href="{{ url_for("member_list") }}">Member List</a>"""
    else:
        t = """Hello! {% with messages = get_flashed_messages() %}
              {% if messages %}
                <ul class="flashes">
                {% for message in messages %}
                  <li>{{ message }}</li>
                {% endfor %}
                </ul>
              {% endif %}
            {% endwith %} <a href="{{ url_for("login") }}">Login</a>"""

    return render_template_string(t)


@app.route('/members')
def member_list():
    if session.get('github_access_token') is None:
        return redirect(url_for('index'))

    after = request.args.get('after')
    before = request.args.get('before')
    customers = stripe.Customer.list(limit=25, starting_after=after, ending_before=before)

    return render_template('members.html', customers=customers)


@app.route('/members/<string:customer_id>')
def show_member(customer_id):
    if session.get('github_access_token') is None:
        return redirect(url_for('index'))

    customer = stripe.Customer.retrieve(customer_id)
    pprint.pprint(customer)

    return render_template('show_member.html', customer=customer)


@app.route('/login')
def login():
    if session.get('github_access_token', None) is None:
        return github.authorize()
    else:
        return 'Already logged in'


@app.route('/logout')
def logout():
    session.pop('github_access_token', None)
    session.pop('github_login', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
