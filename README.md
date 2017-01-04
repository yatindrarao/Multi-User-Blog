# Multi User Blog
Project is available at: https://multi-blog-153004.appspot.com/blog

A multi user blog where user can do theses things:
- post content
- comment on posts
- like posts

It also comes with separate user accounts with appropriate permissions.

## Getting Started
### Compiling and Running
This webapp is developed in python 2.7. and Google App Engine. To run the program in local environment you need to install Google App Engine.
You can follow this guide: https://cloud.google.com/appengine/docs/python/download 

After installation you can run below command.
```
dev_appserver.py .
```
The default web address would be `localhost:8080`.
Here is the list of pages with their links:
- Signup `/signup`
- Login `/login`
- Welcome `/welcome`
- Blog `/blog`

### Structure of Blog
It has 4 entities User, Post, Comment and Likes to handle the data of blog.

### License

Multi User Blog is available under MIT license.
