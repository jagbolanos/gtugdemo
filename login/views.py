from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
import gdata.gauth
import gdata.docs.client
from django.utils.http import urlencode
from openid.consumer.consumer import Consumer
from openid.store.filestore import FileOpenIDStore
from openid.consumer.consumer import AuthRequest, SUCCESS, FAILURE, CANCEL
from openid.extensions import ax
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.models import User


CONSUMER_KEY = 'anonymous'
CONSUMER_SECRET = 'anonymous'

OAUTH_SCOPE=['http://www.google.com/m8/feeds/',
             'http://docs.google.com/feeds/',
             'http://spreadsheets.google.com/feeds/',
             'http://mail.google.com/mail/feed/atom/',
             'http://www.google.com/calendar/feeds/',
             'http://docs.googleusercontent.com',
             #add these if we decide to go with the new gdata library:
             #'https://docs.googleusercontent.com',
             #'https://spreadsheets.google.com/feeds/',
             #'https://docs.google.com/feeds/',
             ]

def index(request):
    if request.method == 'POST':
        username = request.POST['email']
        password = request.POST['password']
        user = authenticate(username=username,password=password)
        if user is not None:
            login(request, user)

    if request.user is not None and request.user.is_authenticated():
            return redirect(to="http://%s/" % request.get_host())
        
    return render_to_response('login.html', locals(), context_instance=RequestContext(request))

def logout_view(request):
    logout(request)
    request.session.flush()
    return index(request)

def register_user(username, firstname, lastname, email, password=None):

    try:
        User.objects.get(username=username)
    except:
        user = User.objects.create_user(username=username, email=email, password=password)
        user.first_name = firstname
        user.last_name = lastname
        user.save()

        return True

    return False

def register(request):
    if request.method == 'POST':
        username = request.POST['email']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        email = request.POST['email']
        password = request.POST['password']

        if register_user(username, firstname, lastname, email, password):
            return index(request)
        else:
            print "El usuario ya esta registrado"


    return redirect(to='http://%s/' % request.get_host())


    #SCOPES = ['https://docs.google.com/feeds/', 'https://www.google.com/calendar/feeds/']
    #client = gdata.docs.client.DocsClient(source='Escolarea-Demo GTUG-v1')

    #oauth_callback_url = 'http://%s/get_access_token' % request.get_host()
    #request_token = client.GetOAuthToken(SCOPES, oauth_callback_url, CONSUMER_KEY, consumer_secret=CONSUMER_SECRET)
    #url=request_token.generate_authorization_url(google_apps_domain=domain)
    ##return render_to_response('login.html', locals(), context_instance=RequestContext(request))
    #return redirect(to=str(request_token.generate_authorization_url(google_apps_domain=domain)))
    #return hardcodedopenid(request, domain)

def domainlogin(request, domain):
    return libopenid(request, domain)

def defaultlogin(request):
    if 'domain' in request.REQUEST:
        return domainlogin(request, request.REQUEST['domain']) 
    return domainlogin(request, 'default') 

def libopenid(request, domain):
    if request.user is not None and request.user.is_authenticated():
            return redirect(to="http://%s/" % request.get_host())

    if domain is 'default':
        discovery_url = "https://www.google.com/accounts/o8/id"
    else:
        discovery_url = "https://www.google.com/accounts/o8/site-xrds?hd=%s" % domain

    consumer = Consumer(request.session, FileOpenIDStore('/tmp/gtugdemo'))
    auth_request = consumer.begin(discovery_url)

    ax_request = ax.FetchRequest()
    ax_request.add(ax.AttrInfo('http://axschema.org/namePerson/first',required=True))
    ax_request.add(ax.AttrInfo('http://axschema.org/namePerson/last',required=True))
    ax_request.add(ax.AttrInfo('http://axschema.org/contact/email',required=True))
    auth_request.addExtension(ax_request)

    redirect_url = auth_request.redirectURL(realm='http://%s/' % request.get_host(), return_to='http://%s/login/callback' % request.get_host())

    oauth_query = {
             'openid.ns.oauth': 'http://specs.openid.net/extensions/oauth/1.0',
             'openid.oauth.consumer': request.get_host(),
             'openid.oauth.scope': ' '.join(OAUTH_SCOPE), 
        }

    redirect_url += "&%s" % urlencode(oauth_query)
    print redirect_url
    #print str(request.session.keys())
    #return render_to_response('login.html', locals(), context_instance=RequestContext(request))
    return redirect(to=redirect_url) 

def callback(request):
    consumer = Consumer(request.session, FileOpenIDStore('/tmp/gtugdemo'))
    
    openid_response = consumer.complete(request.REQUEST, 'http://%s/login/callback' % request.get_host())
    
    if openid_response.status == SUCCESS:
        print "SUCCESS"
        ax_response = ax.FetchResponse.fromSuccessResponse(openid_response)
        if ax_response:
            ax_items = {
                    'firstname': ax_response.get(
                        'http://axschema.org/namePerson/first'),
                    'lastname': ax_response.get(
                        'http://axschema.org/namePerson/last'),
                    'email': ax_response.get(
                        'http://axschema.org/contact/email'),
                    }
            
            username = ''.join(ax_items['email'])
            firstname = ''.join(ax_items['firstname'])
            lastname = ''.join(ax_items['lastname'])
            email = ''.join(ax_items['email'])
            register_user(username, firstname , lastname , email)
            print "%s %s %s" % (firstname, lastname, email)
            user = User.objects.get(username=username)
            user.backend='django.contrib.auth.backends.ModelBackend'
            login(request, user)
            return redirect(to='http://%s/' % request.get_host())
                
    if openid_response.status == FAILURE:
        print "NOOOOOOOOOOO: %s" % openid_response.message
    
    return render_to_response('login.html', locals(), context_instance=RequestContext(request))

def hardcodedopenid(request, domain):
    parameters = {
        'openid.mode': "checkid_setup",
        'openid.ns': "http://specs.openid.net/auth/2.0",
        'openid.return_to': 'http://%s/login/callback' % request.get_host(),
        #'openid.return_to': 'http://test.escolarea.com/login/callback',                
        'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select',
        'openid.identity':'http://specs.openid.net/auth/2.0/identifier_select',
        'openid.assoc_handle': CONSUMER_SECRET,
        'openid.realm': 'http://%s' % request.get_host(),
        'openid.ns.ax': "http://openid.net/srv/ax/1.0",
        'openid.ax.mode': "fetch_request",
        'openid.ax.required': "firstname,lastname,email",
        'openid.ax.type.email': "http://axschema.org/contact/email",
        'openid.ax.type.firstname': "http://axschema.org/namePerson/first",
        'openid.ax.type.lastname': "http://axschema.org/namePerson/last",
        'openid.ns.oauth': 'http://specs.openid.net/extensions/oauth/1.0',
        'openid.oauth.consumer': CONSUMER_KEY,
        'openid.oauth.scope': ' '.join(OAUTH_SCOPE), 
        }

    if domain is 'default':
        url = "https://www.google.com/accounts/o8/ud?%s" % urlencode(parameters)
    else:
        url = "https://www.google.com/a/%s/o8/ud?be=o8&%s" % (domain, urlencode(parameters))

    print url
    return redirect(to=url)
