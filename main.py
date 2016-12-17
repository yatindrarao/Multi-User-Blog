import webapp2
import os
import jinja2
import urllib
import re
from google.appengine.ext import db
import hmac
import hashlib
import random
import string

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Cookie hashing
SECRET = 'imsosecret'
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# Password Hashing
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(",")[1]
    return h == make_pw_hash(name, pw, salt)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)
    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))
    def set_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/'% (name, cookie_val))
    def get_username(self):
        return self.request.cookies.get('username')
    def valid_user(self):
        username = self.get_username()
        if check_secure_val(username):
            return True
        else:
            return False

class WelcomePage(Handler):
    def get(self):
        username = self.get_username()
        user_name = check_secure_val(username)
        if user_name:
            self.render("welcome.html",username=user_name)
        else:
            self.redirect("/login")

class Login(Handler):
    def get(self):
        self.render("login.html")
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        has_error = False
        if username and password:
            u = db.GqlQuery("select * from User where username = '%s'" % username)
            user = u.get()
            h = user.password

            if user and valid_pw(username, password, h):
                self.set_cookie('username',str(username))
                self.redirect("/welcome")
            else:
                has_error = True
                login_error = "Invalid login"
                self.render("login.html", login_error=login_error)
        else:
            has_error = True
            login_error = "Invalid login"
            self.render("login.html", login_error=login_error)


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.redirect("/login")


class SignupForm(Handler):
    """docstring for SignupForm Class."""
    def get(self):
        if self.request.get("username"):
            pass
        self.render("signupform.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username = username, email = email)

        has_error = False

        if self.invalid_username(username=username):
            has_error = True
            params["username_error"] = "That's not a valid username."
        elif self.user_exists(username=username):
            has_error = True
            params["username_error"] = "User already exists!"
        if self.invalid_password(password=password):
            has_error = True
            params["password_error"] = "That was not a valid password."
        else:
            if self.invalid_verify(password=password,verify=verify):
                has_error = True
                params["verify_error"] = "Your password did not match."

        if email and self.invalid_email(email=email):
            has_error = True
            params["email_error"] = "That's not a valid email"

        if has_error:
            self.render("signupform.html", **params)
        else:
            password = make_pw_hash(username,password)
            user = User(username=username, password=password, email=email)
            user.put()
            self.set_cookie('username',str(username))
            self.redirect("/welcome")

    def invalid_username(self,username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return not USER_RE.match(username)
    def invalid_email(self,email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return not EMAIL_RE.match(email)
    def invalid_password(self,password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return not PASS_RE.match(password)

    def invalid_verify(self,password,verify):
        if password != verify:
            return True;
        else:
            return False;
    def user_exists(self, username):
        user = db.Query(User).filter("username = ", username).fetch(1)
        if user:
            return True

# Blog Code
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created_at = db.DateTimeProperty(auto_now_add = True)
    #
    # def render(self):
    #     self._render_text = self.content.replace('\n', '<br>')
    #     return render_str("post.html", post=self)

class MainPage(Handler):
    def get(self):
        if self.valid_user():
            posts = db.GqlQuery("SELECT * from Post ORDER BY created_at DESC")
            self.render("blog.html", posts=posts)
        else:
            self.redirect("/login")

class BlogPost(Handler):
    def get(self, id):
        if self.valid_user():
            post = Post.get_by_id(int(id))
            if post:
                self.render("post.html", post=post)
            else:
                self.error(404)
        else:
            self.redirect("/login")

class NewPost(Handler):
    def get(self):
        if self.valid_user():
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            post = Post(subject=subject, content=content)
            post.put()
            self.redirect("/blog/%s" % post.key().id())
        else:
            error = "subject and content both are required!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)

class EditPost(Handler):
    def get(self, id):
        if self.valid_user():
            post = Post.get_by_id(int(id))
            self.render("editpost.html", subject=post.subject, content=post.content, id=id)
        else:
            self.redirect("/login")

    def post(self, id):
        subject = self.request.get("subject")
        content = self.request.get("content")
        post = Post.get_by_id(int(id))
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect("/blog/%s" % post.key().id())
        else:
            error = "subject and content both are required!"
            self.render("editpost.html", subject=subject, content=content, id=id, error=error)

app = webapp2.WSGIApplication([('/signup', SignupForm),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', WelcomePage),
                               ('/blog', MainPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/(\d+)/edit', EditPost),
                               ('/blog/(\d+)', BlogPost)
                               ], debug=True)
