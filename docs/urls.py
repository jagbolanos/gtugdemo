from django.conf.urls.defaults import *


urlpatterns = patterns('',
    (r'^list/', 'gtugdemo.docs.views.list'),
)
