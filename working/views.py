# Copyright 2005-2011 FindMeOn Inc., Jonathan Vanasco, and misc contributors
# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php

from webob.exc import HTTPException

def osn_HTTPException(context, request):
    """This is a convenience view for handling redirects.  You could honestly do this yourself, as its one line.  This is just here for reference.
    
    usage:
    ----------
    from webob.exc import HTTPException
    from pyramid_opensocialnetwork.views import osn_HTTPException

    def add_handlers(config):
        config.add_view(osn_HTTPException, context=HTTPException)
    ----------

    """
    return context

