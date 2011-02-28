# Copyright 2005-2011 FindMeOn Inc., Jonathan Vanasco, and misc contributors
# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php

from pyramid.httpexceptions import HTTPFound

import pyramid
import logging

log = logging.getLogger(__name__)


class AttributeSafeObj(object):
    """Inspired by Pylons.  Returns '' unless the first 2 chars are __
    """
    def __getattr__(self, name):
        try:
            return object.__getattribute__(self, name)
        except AttributeError : 
            if name[0:2] != '__':
                return ''
            raise


class osnMetaObject(AttributeSafeObj):
    keywords = ''
    title = ''
    description = ''
    medium = ''
    image_src = ''


class osnUserInfo(AttributeSafeObj):
    pass


class osnBaseHandler(object):
    """core basehandler class.  you will want to subclass this.
    
    variables and methods all lead with osn_ or _osn_
    methods should not be subclassed
	    osn_  leading variables can be subclassed
	    _osn_ leading variables should not be subclassed
	    
    """
    _DEBUG= True
    _DEBUG_BASES= False
    
    ## these can all be subclassed

    osn_valid_referers_regex = []

    osn_require_loggedin= False
    osn_require_loggedout= False
    osn_require_preview_cookie= False
    osn_require_local_referer= False
    osn_require_loggedout= False

    osn_cookie_autologin__support= False
    osn_cookie_autologin__login_url= '/login/automatic'
    osn_cookie_autologin__name= 'autologin'
    osn_cookie_autologin__maxage= 31536000

    osn_preview__base_url = '/preview/' # ensure the trailing
    osn_preview__error_base_url= '/preview/error/'
    osn_error_base_url= '/error/'
    osn_login_url= '/account/login/'
    osn_already_loggedin_url = '/account/home'
    osn_invalid_referer_url = '/error/'
    
    
    osn_cookie__domains= ['127.0.0.1']
    osn_cookie__path = '/'

    osn_cookie_preview__name = 'preview'
    osn_cookie_preview__maxage = 31536000
    osn_cookie_userinfo__name= 'userinfo'
    osn_cookie_userinfo__maxage= 31536000
    
    osn_site_hash_seed_cookies= '1234567890'
    



    ## private variables
    _osn_is_preview_allowed= None
    _osn_did_init= False
    
    
    def osn_is_url_valid( self, url ):
        return True

    

    def __init__(self, request , force_init=False ):
        """ __init__ = core setup"""
        if self._DEBUG:
            log.debug("osnBaseHandler.__init__")

        # don't ever run twice , which can happen in multiple inheritance
        if self._osn_did_init and not force_init :
            if self._DEBUG:
                log.debug("osnBaseHandler.__init__ ; already run")
            return
        self._osn_did_init= True

        requested_url= request.path_info

        if self._DEBUG:
            log.debug("osnBaseHandler.__init__ ; requested %s" % requested_url )

        # set up some basic stuff
        self.request = request
        self._osn_setup_c()
        
        if self.osn_require_preview_cookie :
            # this just sets up some vars.  we then need to try some session info
            self._osn_setup_for_preview_checks()

        # setup the session stuff
        # we do this before the preview require, because session info may affect preview
        self._osn_setup_session()

        if self._DEBUG_BASES:
            bases= self.__class__.__bases__
            for item in bases:
                log.debug("osnBaseHandler.__init__ ; BASES : %s" % item )

        try_autologin = False
        if self.osn_cookie_autologin__support :
            # if we're logged in, we don't need to autologin.
            if not self.c.osn_is_logged_in:
                if requested_url == self.osn_cookie_autologin__login_url:
                    try_autologin = True
                else:
                    # check if we have an autologin cookie
                    user_id= self.osn_autologin__cookie_check()
                    if user_id:
                        self.request.session['osn.path_before_login'] = requested_url
                        raise pyramid.httpexceptions.HTTPFound( location = self.osn_cookie_autologin__login_url )

        if self.osn_require_preview_cookie:
            if self._DEBUG:
                log.debug("osnBaseHandler.osn_require_preview_cookie ;")

            if not self._osn_preview_allow():
                if not try_autologin:
                    if requested_url[:len(self.osn_error_base_url)] == self.osn_error_base_url or requested_url[:len(self.osn_preview__error_base_url)] == self.osn_preview__error_base_url:
                        # we have this first, to just kill the /preview/error options
                        pass
                    elif requested_url[:len(self.osn_preview__base_url)] != self.osn_preview__base_url :
                        previewable_url= "%s%s" % ( self.osn_preview__base_url , requested_url[1:] ) # [1:] to drop the leading /
                        if not self.osn_is_url_valid(previewable_url):
                            previewable_url= self.osn_preview__base_url
                        else:
                            if request.environ.get('QUERY_STRING'):
                                previewable_url += '?' + request.environ['QUERY_STRING']
                        if self._DEBUG:
                            log.debug("osnBaseHandler.__init__ ; redirecting to preview url - %s" % previewable_url )
                        raise pyramid.httpexceptions.HTTPFound( location = previewable_url )


            # let's do another silly check
            # basically we just want to make sure that we're not showing a preview page to loggedin people
            # this makes the side easier to use , and avoids issues where logged-in people can do lockedown items through the preview pages
            if self.c.osn_is_logged_in :
                self._osn_redirect_away_from_preview( requested_url )

        else:
            # basically we just want to make sure that we're not showing a preview page 
            self._osn_redirect_away_from_preview( requested_url )
                
                    
        if self.osn_require_local_referer and not try_autologin :
            self._osn_redirect_on_invalid_referer()

        if self.osn_require_loggedout and not try_autologin :
            self._osn_redirect_on_auth()

        # Authentication osn_required?
        if self.osn_require_loggedin and not try_autologin :
            if not self.c.osn_is_logged_in:
                # Remember where we came from so that the user can be sent there
                # after a successful login
                self.request.session['osn.path_before_login'] = requested_url
                if self._DEBUG:
                    log.debug("osnBaseHandler.__init__ ; redirect to my login (BaseHandler_Require_LoggedIn)")
                raise pyramid.httpexceptions.HTTPFound( location= self.osn_login_url )




        


    def _osn_form_reprint( self , form , print_method ):
        """reprints a dedicated form function via formencode/htmlfill.  this was offered to pyramid_simpleform upstream, and will probably leave soon
        
            usage:
            
            class LoginHander(osnBaseHandler_Require_LoggedOut):

                def login(self):
                    if submit == 'POST':
                        return self._login_submit()
                    return self._login_print()
                
                def _login_print(self):
                    render /login.mako
                
                def _login_submit(self):
                    form= pyramid_simpleform_form()
                    if not form.validate():
                        return self._osn_form_reprint( form , self._login_print )
        """
        form_response= print_method()
        form_response.unicode_body= form.htmlfill(str(form_response.body))
        return form_response




    def _osn_setup_c(self):
        """setup basic c vars.  we require self.request to be defined.
        """
        self.c = self.request.tmpl_context

        self.c.osn_meta= osnMetaObject()

        self.c.osn_is_logged_in = False
        self.c.osn_is_logged_in_admin= False
        
        self.c.osn_is_view_as_preview = None
        self.c.osn_is_preview_ok = None




    def _osn_setup_for_preview_checks(self):
        """sets c.osn_is_view_as_preview as True ; self._osn_is_preview_allowed.  if a preview cookie is found, this will later be set to false.
        """
        self._osn_is_preview_allowed= False
        self.c.osn_is_view_as_preview= True




    def _osn_setup_session(self):
        """basic user session setup
        """
        # init the osn.user_id if needed
        if 'osn.user_id' not in self.request.session:
             self.request.session['osn.user_id']= None
        # init the osn.user_info if needed
        if 'osn.user_info' not in  self.request.session or not  self.request.session['osn.user_id']:
             self.request.session['osn.user_info']= osnUserInfo()
        # toggle the loggedin status if ok
        if 'osn.user_id' in  self.request.session and self.request.session['osn.user_id']:
            self.c.osn_is_logged_in= True
            if 'osn.is_admin' in  self.request.session and  self.request.session['osn.is_admin']:
                self.c.osn_is_logged_in_admin= True




    def _osn_redirect_on_invalid_referer(self):
        """redirects user to no-referer security page if unregistered referer header
        """
        referer= self.request.environ.get('HTTP_REFERER')
        if referer is None:
            referer= ''
        valid= False
        
        for regex in self.osn_valid_referers_regex:
            if regex.match( referer ):
                valid= True
        if not valid:
            raise pyramid.httpexceptions.HTTPFound( location = self.osn_invalid_referer_url ) 




    def _osn_redirect_on_auth(self):
        """ redirects user to logged_in error page if logged in
        """
        if self.c.osn_is_logged_in :
            raise pyramid.httpexceptions.HTTPFound( location = self.osn_already_loggedin_url )




    def osn_dont_cache( self ):
        """ let's just never cache this.  k? thx. bye.
        """
        response.cache_control= 'no-store,no-cache,must-revalidate,max-age=0,post-check=0,pre-check=0,must-revalidate'
        response.pragma= 'no-cache'
        response.expires= '0'




    def _osn_preview_allow( self ):
        
        if self._osn_is_preview_allowed is not None:
            return self._osn_is_preview_allowed

        if self.osn_preview__is_ok() :
            if self._DEBUG:
                log.debug("osnBaseHandler._osn_preview_allow ; self.osn_preview__is_ok = True")
            self.c.osn_is_view_as_preview= False
            self.c.osn_is_preview_ok= True
            self._osn_is_preview_allowed= True

        elif self.osn_preview__cookie_check():
            if self._DEBUG:
                log.debug("osnBaseHandler._osn_preview_allow ; self.osn_preview__is_ok = False")
                log.debug("osnBaseHandler._osn_preview_allow ; self.osn_preview__cookie_check = True")
            self.osn_preview__grant(True)
            self.c.osn_is_view_as_preview= False
            self.c.osn_is_preview_ok= True
            self._osn_is_preview_allowed= True

        elif self.c.osn_is_logged_in:
            # if they're logged in, assume that they can preview
            # TODO: This is potentially not what we want to do
            # there may be instances where we want them to be logged in, but not previewable
            # in any instance, without this field, we can run into an issue where there is an endless loop caused by no preview yet a login
            self.osn_preview__grant(True)
            self.c.osn_is_view_as_preview= False
            self.c.osn_is_preview_ok= True
            self._osn_is_preview_allowed= True
            
        return self._osn_is_preview_allowed


    def _osn_redirect_away_from_preview( self , requested_url ):
        root_url_size= len(self.osn_preview__base_url)
    
        # match on :root_url_size to ensure the / directory
        if requested_url[:root_url_size] == self.osn_preview__base_url:
            # fix on root_url_size-1: to ensure the / root
            fixed_url= requested_url[root_url_size - 1:] 
            if request.environ.get('QUERY_STRING'):
                fixed_url += '?' + request.environ['QUERY_STRING']
            if self._DEBUG:
                log.debug("osnBaseHandler._osn_redirect_away_from_preview ; redirecting to fixed url - %s" % fixed_url )
            raise pyramid.httpexceptions.HTTPFound( location = fixed_url )





    def osn_preview__enable():
        """enables preview cookies
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_preview__enable" )
        osn_preview__cookie_set()
        osn_preview__grant( True )

    def osn_preview__disable():
        """kills cookie and session
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_preview__disable" )
        osn_preview__cookie_kill()
        osn_preview__grant( False )

    def osn_preview__is_ok():
        """osn_preview__is_ok - core preview action
           returns true if 'osn.is_preview_ok' in session
           this checks session, not cookie
           cookie check is different
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_preview__is_ok" )
        if 'osn.is_preview_ok' in self.request.session and self.request.session['osn.is_preview_ok']:
            return True
        return False
        
    def osn_preview__grant( grant ):
        """osn_preview__grant - core preview action
           updates the session with a preview bool
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_preview__grant ; setting to - %s" % osn_preview__grant )
        if grant:
            self.request.session['osn.is_preview_ok'] = True
        else:
            if 'osn.is_preview_ok' in self.request.session:
                del self.request.session['osn.is_preview_ok']

    def osn_preview__cookie_check():
        """ checks preview cookie
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_preview__cookie_check")
        if self.osn_cookie_preview__name in self.request.cookies:
           return True
        return False
    
    def osn_preview__cookie_set():
        """ sets preview cookie
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_preview__cookie_set")
        for domain in self.osn_cookie__domains:
            response.set_cookie( self.osn_cookie_preview__name , 1, max_age=self.osn_cookie_preview__maxage , path=self.osn_cookie__path , domain=domain )
    
    def osn_preview__cookie_kill():
        """ kills preview cookie
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_preview__cookie_kill")
        for domain in self.osn_cookie__domains:
            response.delete_cookie( self.osn_cookie_preview__name , path=self.osn_cookie__path , domain=domain )

            

    def osn_userinfo__cookie_set( cookie_dict={} ):
        """ creates a cookie of client-side data.  : is an unsupported character , it is used as a delimiter
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_userinfo__cookie_set")
        stringed= []
        for k in cookie_dict.keys():
            stringed.append( "%s:%s" % ( k , cookie_dict[k] ) )
        stringed= '::'.join(stringed)
        for domain in self.osn.cookie__domains:
            response.set_cookie( self.osn_cookie_userinfo__name , stringed, max_age=self.osn_cookie_userinfo__maxage , path=self.osn_cookie__path , domain=domain )
        
    def osn_userinfo__cookie_kill():
        """ kills client-side data cookie
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_userinfo__cookie_kill")
        for domain in self.osn.cookie__domains:
            response.delete_cookie( self.osn_cookie_userinfo__name , path=self.osn_cookie__path , domain=domain )
    
    
    
    

    def osn_autologin__cookie_kill():
        """ kills autologin cookie
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_autologin__cookie_kill")
        if self.osn_cookie_autologin__support:
            if self.osn_cookie_autologin__name in request.cookies:
                if self._DEBUG:
                    log.debug("osnBaseHandler.osn_autologin__cookie_kill; killing - %s" % self.osn_cookie_autologin__name )
                for domain in self.osn_cookie__domains:
                    response.delete_cookie( self.osn_cookie_autologin__name, path=self.osn_cookie__path , domain=domain )
    
    def osn_autologin__cookie_check():
        """ cehecks autologin cookie ; autologin cookies are hash protected
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_autologin__cookie_check")
        if not self.osn_cookie_autologin__support:
            return False
        if self.osn_cookie_autologin__name in request.cookies:
            user_identifier = self._osn_autologin__hash_validate( request.cookies[ self.osn_cookie_autologin__name] )
            if user_identifier:
                if self._DEBUG:
                    log.debug("osnBaseHandler.osn_autologin__cookie_check; valid - %s" % user_identifier )
                return user_identifier
            else:
                if self._DEBUG:
                    log.debug("osnBaseHandler.osn_autologin__cookie_check; invalid")
                self.osn_autologin__cookie_kill()
        return False
    
    def osn_autologin__cookie_set( user_identifier ):
        """ sets autologin cookie ; autologin cookies are hash protected
        """
        if self._DEBUG:
            log.debug("osnBaseHandler.osn_autologin__cookie_set")
        if self.osn_cookie_autologin__support:
            hashed= self._osn_autologin__hash_generate( user_identifier )
            for domain in self.osn_cookie__domains:
                response.set_cookie( self.osn_cookie_autologin__name, hashed, max_age=self.osn_cookie_autologin__maxage , path=self.osn_cookie__path , domain=domain )
    
    def _osn_autologin__checksum_generate( user_identifier ):
        return md5.md5( "osn.autologin:%s:%s" % ( self.osn_site_hash_seed_cookies , user_identifier ) ).hexdigest()
    
    def _osn_autologin__checksum_validate( checksum , user_identifier ):
        if checksum != self._osn_autologin__checksum_generate( user_identifier ) :
            return False
        return True
    
    def _osn_autologin__hash_generate( user_identifier ):
        return "%s:%s" % ( user_identifier , self._osn_autologin__checksum_generate(user_identifier) )
    
    def _osn_autologin__hash_validate( hash ):
        if not hash: 
            return False
        components= hash.split(':')
        if len(components) != 2:
            return False
        ( user_identifier , checksum )= components
        if not self._osn_autologin__checksum_validate( checksum , user_identifier ):
            return False
        return user_identifier



class osnBaseHandler_Require_LoggedIn(osnBaseHandler):
    """
        This is a basic controller for you to inherit.
        It is based off the default Pylons controller, but contains some extra features
       
        self.osn_require_loggedin (True)
            must someone be logged in?
            if not, rediret to /my/login
        
        This can be stacked with other controllers like:
            osnBaseHandler_Require_LoggedOut
            osnBaseHandler_Preview_Lockdown
            osnBaseHandler_Preview_Passthrough
        
        It inherits from osnBaseHandler, so you do not need to stack it as well

    """
    osn_require_loggedin= True


class osnBaseHandler_Require_LoggedOut(osnBaseHandler):
    """
       This is a basic controller for you to inherit.
       It is based off the default Pylons controller, but contains some extra features
       
       self.osn_require_loggedout (True)
            must someone be logged out?
            if not, rediret to /my/-error/logged_in

        This can be stacked with other controllers like:
            osnBaseHandler_Require_LoggedIn
            osnBaseHandler_Preview_Lockdown
            osnBaseHandler_Preview_Passthrough
        
        It inherits from osnBaseHandler, so you do not need to stack it as well
    """
    osn_require_loggedout= True


class osnBaseHandler_Preview_Lockdown(osnBaseHandler):
    """
       This is a basic controller for you to inherit.
       It is based off the default Pylons controller, but contains some extra features
       
       self.osn_require_preview_cookie (True)
            must a preview cookie be found?
            if not, rediret to /preview

        This can be stacked with other controllers like:
            BaseHandler_Require_LoggedIn
            BaseHandler_Require_LoggedOut
            BaseHandler_Preview_Passthrough
        
        It inherits from osnBaseHandler, so you do not need to stack it as well
    """
    osn_require_preview_cookie= True



class osnBaseHandler_Preview_Passthrough(osnBaseHandler):
    """
       This is a basic controller for you to inherit.
       It is based off the default Pylons controller, but contains some extra features
       
       self.osn_require_preview_cookie (False)
            must a preview cookie be found?
            if not, rediret to /preview

        This can be stacked with other controllers like:
            BaseHandler_Require_LoggedIn
            BaseHandler_Require_LoggedOut
            BaseHandler_Preview_Lockdown
        
        It inherits from osnBaseHandler, so you do not need to stack it as well
    """
    osn_require_preview_cookie= False

