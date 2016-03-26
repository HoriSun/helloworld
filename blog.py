#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import bcrypt # encryption? what kind of? (password hashing)
import concurrent.futures # multiprocess
import MySQLdb 
import markdown
import os.path
import re # regrex 
import subprocess # multiprocess
import torndb # tornado db
import tornado.escape # ???
from tornado import gen # ???
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import unicodedata # unicode 

from tornado.options import define, options

# [HSUN] running port and MySQL port should be changed to the other unusual ports
define("port", default=8888, help="run on the given port", type=int)
define("mysql_host", default="127.0.0.1:3306", help="blog database host")
define("mysql_database", default="blog", help="blog database name")
define("mysql_user", default="blog", help="blog database user")
define("mysql_password", default="blog", help="blog database password")


# A thread pool to be used for password hashing with bcrypt.
executor = concurrent.futures.ThreadPoolExecutor(2)


class Application(tornado.web.Application):
    def __init__(self):
        # routing
        handlers = [
            (r"/", HomeHandler),
            (r"/sub/SSC", SSCHandler),
            (r"/Agreement", AgreementHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            (r"/auth/register",AuthRegisterHandler),
        ]
        # basic settings
        settings = dict(
            blog_title=u"98398 彩票网",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            #ui_modules={"Entry": EntryModule}, # ???
            xsrf_cookies=True,
            #cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            cookie_secret="F3/XPvMFEeWOsCS2/UVDhb6tVd2ASEo3qaAEsbUxGSA=", #[HSUN] use `cookie_secret_gen.py` to generate a new one
            login_url="/auth/login",
            debug=False,
        )
        super(Application, self).__init__(handlers, **settings)
        # Have one global connection to the blog DB across all handlers
        self.db = torndb.Connection(
            host=options.mysql_host, database=options.mysql_database,
            user=options.mysql_user, password=options.mysql_password)

        self.maybe_create_tables()

    def maybe_create_tables(self):
        try:
            self.db.get("SELECT COUNT(*) from entries;")
        except MySQLdb.ProgrammingError:
            subprocess.check_call(['mysql',
                                   '--host=' + options.mysql_host,
                                   '--database=' + options.mysql_database,
                                   '--user=' + options.mysql_user,
                                   '--password=' + options.mysql_password],
                                  stdin=open('schema.sql'))


cookie_key_user = "lottery_client"

class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        user_id = self.get_secure_cookie(cookie_key_user)
        if not user_id: return None
        return self.db.get("SELECT * FROM user WHERE id = %s", int(user_id))


class HomeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render("Main.html")


class SSCHandler(BaseHandler):
    def get(self):
        self.render("SSC.html")


class AgreementHandler(BaseHandler):
    def get(self):
        self.render("Agreement.html")


class AuthRegisterHandler(BaseHandler):
    def get(self):
        self.render("Register.html")

    @gen.coroutine
    def post(self):
        if(bool(self.db.get("SELECT * FROM user WHERE name=%s", self.get_argument("name")))):
            #raise tornado.web.HTTPError(400, "username already exists")
            self.write({'success':False,'message':'username already exists'})
            self.finish()


        hashed_password = yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            bcrypt.gensalt())

        author_id = self.db.execute(
            "INSERT INTO user (name, hashed_password) "
            "VALUES (%s, %s)",
            self.get_argument("name"),
            hashed_password)
        self.set_secure_cookie(cookie_key_user, str(author_id))
        self.write({'success':True})
        self.finish()
        #self.redirect(self.get_argument("next", "/"))

class AuthLoginHandler(BaseHandler):
    def get(self):
        self.render("Login.html", error=None)

    @gen.coroutine
    def post(self):
        user = self.db.get("SELECT * FROM user WHERE name = %s",
                             self.get_argument("name"))
        if not user:
            self.render("Login.html", error="username not found")
            return
        print self.get_argument("password")
        print tornado.escape.utf8(self.get_argument("password"))
        print user
        print tornado.escape.utf8(user.hashed_password)
        hashed_password = yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(user.hashed_password))
        if hashed_password == user.hashed_password:
            self.set_secure_cookie(cookie_key_user, str(user.id))
            #self.redirect(self.get_argument("next", "/Agreement"))
            self.redirect("/Agreement")
        else:
            self.render("Login.html", error="incorrect password")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie(cookie_key_user)
        self.redirect(self.get_argument("next", "/"))


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
