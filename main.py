import webapp2
import os
import jinja2
import urllib
import re
from google.appengine.ext import db
import hmac

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)

SECRET = 'imsosecret'
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


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
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'% (name, cookie_val))
class WelcomePage(Handler):
    def get(self):
        username = self.request.cookies.get('username')
        user_name = check_secure_val(username)
        if user_name:
            self.render("welcome.html",username=user_name)
        else:
            self.redirect("/signup")

class Login(Handler):
    def get(self):
        self.render("login.html")
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        has_error = False
        if username and password:
            user = db.Query(User).filter("username = ", username).filter("password = ", password).fetch(1)
            if not user:
                has_error = True
                login_error = "Invalid login"
                self.render("login.html", login_error=login_error)
            else:
                self.set_cookie('username',str(username))
                self.redirect("/welcome")
        else:
            has_error = True
            login_error = "Invalid login"
            self.render("login.html", login_error=login_error)


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.redirect("/signup")


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

app = webapp2.WSGIApplication([('/signup', SignupForm),('/login',Login),('/logout',Logout),('/welcome',WelcomePage)], debug=True)
