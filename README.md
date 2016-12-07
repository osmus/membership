# OSM US Membership App

This is a relatively simple web app that works in coordination with Stripe to offer a way to join OpenStreetMap US. It will then process webhooks from Stripe to send emails to the users and post to a Slack channel.

## Setup and Install

This web app is designed to be run on Heroku (or any system that can handle a `Procfile`), but it can be run without Heroku, too. In general, to get this running on Heroku:

```
git clone git@github.com:osmus/membership.git
cd membership
heroku create
git push heroku
heroku open
```

You'll also need to sign up for GitHub, MailGun, Slack, Sentry, and Stripe. The various keys and URLs that these services give you will be passed to and used by the app via environment variables:

| Environment Variable | Description |
|:---------------------|:------------|
| `DEBUG`              | Set to `false` to decrease the verbosity of logs and to prevent stack traces from showing up on the user's browser.
| `SECRET_KEY`         | Set to a random string so that session tokens are generated securely.
| `STRIPE_SECRET_KEY`  | Your Stripe secret key. While developing or testing, you should use Stripe's test mode key.
| `STRIPE_PUBLISHABLE_KEY` | Your Stripe "publishable key" that links the Checkout.js payment form to your Stripe account.
| `SLACK_URL`          | URL for an "Incoming Webhook" integration on your Slack team. This allows the app to post notifications to your Slack team when interesting things happen.
| `MAILGUN_API_KEY`    | Your MailGun API key to use when sending email.
| `MAILGUN_SANDBOX`    | The domain name you configured while setting up MailGun.
| `GITHUB_CLIENT_ID`   | The OAuth client ID for a GitHub application (preferably owned by your GitHub organization) to be used when checking login credentials.
| `GITHUB_CLIENT_SECRET` | The OAuth client secret for the GitHub application referred to be the above client ID.
| `GITHUB_TEAM_ID`     | The team ID people must be a member of to allow access to your member list.
| `SENTRY_DSN`         | The Sentry DSN/URL to use when capturing errors and stack traces for debugging.

## Limitations

Right now this system relies heavily on Stripe. It has no database of its own and stores all details for your users on the Stripe "customer" object. This means that searching and browsing existing members is very limited or just plain isn't supported.

The system will send emails and push to Slack during the webhook request cycle, so if either of these steps takes too long (if either of those systems is down, for example) then the webhook will probably fail and get retried. This might result in a user getting more than one email welcoming them to the organization or multiple messages in Slack.

It's rather difficult (and I don't offer any built-in tools to help) to find your GitHub team ID. I did it by manually mucking around with the GitHub API client in Python but didn't save the code.
