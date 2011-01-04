from django.conf.urls.defaults import *


urlpatterns = patterns('',
    (r'^$', 'login.views.index'),
    (r'^(?P<domain>([a-z_\-]|\d)+\.[a-z]{2,3})/$', 'login.views.domainlogin'),
    (r'^google/$', 'login.views.defaultlogin'),
    (r'^register/$', 'login.views.register'),
    (r'^callback/$', 'login.views.callback'),
)
