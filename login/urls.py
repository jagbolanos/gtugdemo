from django.conf.urls.defaults import *


urlpatterns = patterns('',
    (r'^$', 'login.views.index'),
    (r'^(?P<domain>([a-z_\-]|\d)+\.[a-z]{2,3})/$', 'gtugdemo.login.views.domainlogin'),
    (r'^google/$', 'gtugdemo.login.views.defaultlogin'),
    (r'^register/$', 'gtugdemo.login.views.register'),
    (r'^callback/$', 'gtugdemo.login.views.callback'),
)
