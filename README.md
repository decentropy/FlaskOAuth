# FlaskOAuth
Using Flask and RAuth to support authenticating via Twitter, Google, Facebook, Github, LinkedIn, and Reddit

Register for API keys at each service, and add to your flask config, e.g. (below are fake)

OAUTH_CREDENTIALS = {
    'facebook': {
        'id': '104735435285335',
        'secret': 'fbasffs99esdgfasf9abe16f24e06a0'
    },
    'twitter': {
        'id': 'I6OjpF1hl6777797A9ZmfVjH',
        'secret': 'LIHbJudRXFeX27O0YwasfdafssfafVUZvuT7G7f6ej89h3hR'
    },
    'google': {
        'id': '71117522583543535m3jsdgh6cb9p1f5g7.apps.googleusercontent.com',
        'secret': 'ZJLmull2QhhjkhkhkSe971'
    },
    'linkedin': {
        'id': '75hp7897979ygx',
        'secret': 'Z1BPeasfsafJZeYQtA'
    },
    'github': {
        'id': '6a2e48ab789797978c1',
        'secret': '8aaf3bb31a7a5casfasfsaf979d34dd3'
    },
    'reddit': {
        'id': 'aErKRa1b_Z0HKA',
        'secret': 'a4XzIn3535435Xbx_aduKU',
        'useragent': 'yourwebsite.com by /u/yourname'
    }
}

To login, route in flask with the service provider name, e.g.:

@app.route('/authorize/<provider>')
def oauth_authorize(provider):      #oauth start
    oauth = OAuthSignIn.get_provider(provider)
    session['state'] = oauth.state
    session['next'] = request.args.get('next', '')
    return oauth.authorize()

Below will be returned upon successful authorization:

@app.route('/callback/<provider>')
def oauth_callback(provider):       #oauth callback
    oauth = OAuthSignIn.get_provider(provider)
    social_id, username, email, url, jsonme = oauth.callback()
