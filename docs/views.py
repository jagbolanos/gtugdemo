from django.shortcuts import render_to_response
from django.template import RequestContext
import gdata.docs.service

class Entry:
    def __init__(self, text, id):
        self.text = text
        self.id = id

def list(request):

    if request.method == "POST":
        client = gdata.docs.service.DocsService()
        client.ClientLogin(request.POST['email'], request.POST['password'], source="GTUG Balam DEMO")
        listFeed = client.GetDocumentListFeed()
        feed = []
        for entry in listFeed.entry:
            feed.append(Entry(entry.title.text, entry.resourceId.text[entry.resourceId.text.find(':')+1:]))

    return render_to_response('list.html', locals(), context_instance=RequestContext(request))
