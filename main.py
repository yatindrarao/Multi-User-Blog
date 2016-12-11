import webapp2
import os
import jinja2
import urllib
import re

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)
    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

class WelcomePage(Handler):
    def get(self):
        username = self.request.get("username")
        if username:
            self.render("welcome.html",username=username)
        else:
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
            self.redirect("/welcome?username="+username)

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

app = webapp2.WSGIApplication([('/signup', SignupForm),('/welcome',WelcomePage)], debug=True)
