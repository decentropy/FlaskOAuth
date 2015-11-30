from rauth import OAuth1Service, OAuth2Service
from flask import abort, current_app, url_for, request, redirect, session
import json
import string
import random
import requests


def jsondecoder(content):
    try:
        return json.loads(content.decode('utf-8'))
    except Exception:
        return json.loads(content)


class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']
        self.state = ''.join(random.choice(string.ascii_uppercase) for i in range(10))

    def authorize(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name, _external=True)

    def callback(self):
        pass

    def validate_oauth2callback(self):
        if 'code' not in request.args: #dump request if problem
            abort(500, 'oauth2 callback: code not in request.args: \n' + str(request.__dict__))
        if request.args.get('state') != session.get('state'):
            abort(500, 'oauth2 callback: state does not match: \n' + str(request.__dict__))

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]


#https://console.developers.google.com/project/willpaycoin/apiui/credential
class GoogleSignIn(OAuthSignIn): 
    def __init__(self):
        super(GoogleSignIn, self).__init__('google')
        self.service = OAuth2Service(
                name='google',
                client_id=self.consumer_id,
                client_secret=self.consumer_secret,
                authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
                access_token_url='https://www.googleapis.com/oauth2/v4/token',
                base_url='https://www.googleapis.com/oauth2/v3/userinfo'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
                scope='email',
                response_type='code',
                state=self.state,
                redirect_uri=self.get_callback_url())
            )

    def callback(self):
        self.validate_oauth2callback()
        #get token
        oauth_session = self.service.get_auth_session(
                data={'code': request.args['code'],
                      'grant_type': 'authorization_code',
                      'redirect_uri': self.get_callback_url()
                     },
                decoder = jsondecoder
        )
        me = oauth_session.get('').json()
        social_id = 'google$' + me['sub']
        nickname = me.get('name',None) if me.get('name',None) else me['email'].split('@')[0]
        email = me['email'] if me['email_verified']==True else None
        url = me.get('profile', None)
        return (social_id, nickname, email, url, me)



#https://github.com/settings/applications/251139
class GitHubSignIn(OAuthSignIn):  
    def __init__(self):
        super(GitHubSignIn, self).__init__('github')
        self.service = OAuth2Service(
            name='github',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://github.com/login/oauth/authorize',
            access_token_url='https://github.com/login/oauth/access_token',
            base_url='https://api.github.com/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
                state=self.state,
                redirect_uri=self.get_callback_url())
            )

    def callback(self):
        self.validate_oauth2callback()
        #get token
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'redirect_uri': self.get_callback_url()}
        )
        me = oauth_session.get('user').json()
        social_id = 'github$' + str(me['id'])
        nickname = me['login']
        email = None
        url = 'https://github.com/' + me['login'] #TODO: be sure this isn't changed
        return (social_id, nickname, email, url, me)
        


#https://developers.facebook.com/apps/1047596085285335/settings/
class FacebookSignIn(OAuthSignIn):  
    def __init__(self):
        super(FacebookSignIn, self).__init__('facebook')
        self.service = OAuth2Service(
            name='facebook',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://graph.facebook.com/oauth/authorize',
            access_token_url='https://graph.facebook.com/oauth/access_token',
            base_url='https://graph.facebook.com/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
                scope='public_profile,email',
                response_type='code',
                state=self.state,
                redirect_uri=self.get_callback_url())
            )

    def callback(self):
        self.validate_oauth2callback()
        #get token
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()}
        )
        me = oauth_session.get('me?fields=id,name,email,link').json()
        social_id = 'facebook$' + me['id']
        nickname = me['name']
        email = me.get('email', None)
        url = me.get('link', None)
        return (social_id, nickname, email, url, me)


#https://www.linkedin.com/developer/apps
class LinkedInSignIn(OAuthSignIn):  
    def __init__(self):
        super(LinkedInSignIn, self).__init__('linkedin')
        self.service = OAuth2Service(
            name='linkedin',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,              
            authorize_url='https://www.linkedin.com/uas/oauth2/authorization',      
            access_token_url='https://www.linkedin.com/uas/oauth2/accessToken',
            base_url='https://api.linkedin.com/v1/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
                scope='r_basicprofile r_emailaddress',
                response_type='code',
                state=self.state,
                redirect_uri=self.get_callback_url())
            )

    def callback(self):
        self.validate_oauth2callback()
        #get token
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()}, 
            decoder=jsondecoder
        )
        me = oauth_session.get('people/~:(id,first-name,last-name,public-profile-url,email-address)?format=json&oauth2_access_token='+str(oauth_session.access_token), data={'x-li-format': 'json'}, bearer_auth=False).json()
        social_id = 'linkedin$' + me['id']
        nickname = me['firstName'] + ' ' + me['lastName']
        email = me['emailAddress']
        url = me['publicProfileUrl'] #TODO: be sure this didn't change
        return (social_id, nickname, email, url, me)


#https://www.reddit.com/prefs/apps/
class RedditSignIn(OAuthSignIn):  
    def __init__(self):
        super(RedditSignIn, self).__init__('reddit')
        self.service = OAuth2Service(
            name='reddit',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            access_token_url="https://ssl.reddit.com/api/v1/access_token",
            authorize_url="https://ssl.reddit.com/api/v1/authorize",
            base_url='https://api.reddit.com/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
                scope='identity',
                response_type='code',
                state=session.get('state',''),
                redirect_uri=self.get_callback_url())
            )

    def callback(self):
        self.validate_oauth2callback()
        #get token
        client_auth = requests.auth.HTTPBasicAuth(self.consumer_id, self.consumer_secret)
        headers = {"User-Agent": current_app.config['OAUTH_CREDENTIALS']['reddit']['useragent']}
        post_data = {"grant_type": "authorization_code",
            "code": request.args['code'],
            "redirect_uri": self.get_callback_url(),
            "format": "json"}
        response = requests.post("https://ssl.reddit.com/api/v1/access_token", auth=client_auth, headers=headers, data=post_data)
        token_json = response.json()
        token = token_json["access_token"]
        #use token
        headers = {"Authorization": "bearer " + token, "User-Agent": current_app.config['OAUTH_CREDENTIALS']['reddit']['useragent']}
        response = requests.get("https://oauth.reddit.com/api/v1/me", headers=headers)
        #return data
        me = response.json()
        username = response.json()['name']
        social_id = 'reddit$' + username
        email = None 
        url = "https://www.reddit.com/user/" + username
        return (social_id, username, email, url, me)


#https://apps.twitter.com/app/1399020/show
class TwitterSignIn(OAuthSignIn):   
    def __init__(self):
        super(TwitterSignIn, self).__init__('twitter')
        self.service = OAuth1Service(
            name='twitter',
            consumer_key=self.consumer_id,
            consumer_secret=self.consumer_secret,
            request_token_url='https://api.twitter.com/oauth/request_token',
            authorize_url='https://api.twitter.com/oauth/authorize',
            access_token_url='https://api.twitter.com/oauth/access_token',
            base_url='https://api.twitter.com/1.1/'
        )

    def authorize(self):
        request_token = self.service.get_request_token(
            params={'oauth_callback': self.get_callback_url()}
        )
        session['request_token'] = request_token
        return redirect(self.service.get_authorize_url(request_token[0]))

    def callback(self):
        request_token = session.pop('request_token')
        if 'oauth_verifier' not in request.args:
            return None, None, None, None, None
        oauth_session = self.service.get_auth_session(
            request_token[0],
            request_token[1],
            data={'oauth_verifier': request.args['oauth_verifier']}
        )
        me = oauth_session.get('account/verify_credentials.json').json()
        social_id = 'twitter$' + str(me.get('id'))
        nickname = me.get('screen_name')
        email = None
        url = 'https://twitter.com/' + me.get('screen_name')
        return (social_id, nickname, email, url, me)


