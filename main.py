from flask import Flask, request, g, session, redirect, url_for
from flask import render_template_string
from flask_github import GitHub, GitHubError
import os

SECRET_KEY = 'development key'
DEBUG = True

# Set these values
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')

# "osmus" Organization, "Board" Team
TEAM_ID = os.environ.get('GITHUB_TEAM_ID')

# setup flask
app = Flask(__name__)
app.config.from_object(__name__)

# setup github-flask
github = GitHub(app)


@app.route('/')
def index():
    if session.get('github_access_token'):
        t = 'Hello! <a href="{{ url_for("user") }}">Get user</a> ' \
            '<a href="{{ url_for("logout") }}">Logout</a>'
    else:
        t = 'Hello! <a href="{{ url_for("login") }}">Login</a>'

    return render_template_string(t)


@github.access_token_getter
def token_getter():
    return session.get('github_access_token')
    user = g.user
    if user is not None:
        return user.github_access_token


@app.route('/github-callback')
@github.authorized_handler
def authorized(access_token):
    next_url = request.args.get('next') or url_for('index')
    if access_token is None:
        return redirect(next_url)

    session['github_access_token'] = access_token
    return redirect(next_url)


@app.route('/login')
def login():
    if session.get('github_access_token', None) is None:
        return github.authorize()
    else:
        return 'Already logged in'


@app.route('/logout')
def logout():
    session.pop('github_access_token', None)
    return redirect(url_for('index'))


@app.route('/user')
def user():
    access_token = session.get('github_access_token')
    if access_token:
        user = github.get('user')

        member_of_board = False
        try:
            membership = github.get('teams/{}/members/{}'.format(TEAM_ID, user.get('login')))
            if membership.status_code == 204:
                member_of_board = True
        except GitHubError:
            pass

        return "Hi {}, you are{} a member of the OSM US board".format(
            user.get('login'),
            "" if member_of_board else " not",
        )
    else:
        return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
