pyramid_opensocialnetwork
---------
Quick tools to build socially aware applications with pyramid

Documentation: http://github.com/jvanasco/pyramid_opensocialnetwork

More info:  http://findmeon.org


About
-----

pyramid_opensocialnetwork is designed as a series of tools to make developing socially aware web applications faster, while not requiring many application design requirements.


History
-----

FindMeOn.com released "OpenSN (Open Social Network)" in 2006 as an interchange format for encoding social media profiles and data.

Work soon began on Pylons & PHP based systems to allow for quickly exchanging content and building web applications.  Our goal was to make it easier for startups and advertising agencies to get new projects off the ground.  pyramid_opensocialnetwork is a complete rewrite of privately released pylons code.


Usage
-----

This is extremely beta software, and is not packaged for release.  This is currently offered for feedback and improvement.

The only in-progress component currently available is handlers.py

handlers.py provides a core BaseHandler to be subclassed.

This BaseHandler will:
	1. Populate "self" with some useful things for Pylons compliance -- ie: request and c
	2. Provide for cookies that store: preview status, auto-login, user info
	3. Provide a session object for storing user data
	4. Provide a meta object for storing page data for templating
	5. Simplifies form repriting with pyramid_simpleform if you follow a form printing convention

A few things are not fully working ... such as hooks for auto-login.

Everything was placed within the controller to simplify imports.  This may change. 
Everything is nicely tucked away within an osn_ prefix for safety.


Licensing
---------
MIT Open Source License