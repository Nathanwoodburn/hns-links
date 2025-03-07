from flask import Flask, make_response, redirect, request, jsonify, render_template, send_from_directory, render_template_string
import os
import dotenv
import requests
import datetime
import json
import render
import secrets
import nginx
import threading
import nostr as nostr_module

app = Flask(__name__)
dotenv.load_dotenv()

# Get site domains
DOMAINS = os.getenv('DOMAINS')
DOMAINS = json.loads(DOMAINS)

# Add local domains
# DOMAINS.append('localhost:5000')
DOMAINS.append('127.0.0.1:5000')
IP = "0.0.0.0"

try:
    IP = requests.get('https://ipinfo.io/ip').text.strip()
except:
    IP = "Error"

# Get HSD API
HSD_API = os.getenv('HSD_API', '')
HSD_IP = os.getenv('HSD_IP', '127.0.0.1')
HSD_PORT = os.getenv('HSD_PORT', 12037)

# Load cookies
cookies = []

if os.path.isfile('cookies.json'):
    with open('cookies.json') as file:
        cookies = json.load(file)
else:
    with open('cookies.json', 'w') as file:
        json.dump(cookies, file)

if not os.path.isdir('avatars'):
    os.mkdir('avatars')

if not os.path.isdir('sites'):
    os.mkdir('sites')

if not os.path.isdir('certs'):
    os.mkdir('certs')

#Assets routes
@app.route('/assets/<path:path>')
def send_report(path):
    return send_from_directory('templates/assets', path)

@app.route('/https.js')
def httpsJS():
    return send_from_directory('templates', 'https.js')

@app.route('/favicon.png')
def faviconPNG():
    return send_from_directory('templates/assets/img', 'favicon.png')


# Main routes
@app.route('/')
def index():
    if request.host in DOMAINS:        
        if 'auth' in request.cookies:
            auth = request.cookies['auth']
            for i in cookies:
                if i['cookie'] == auth:
                    return render_template('index.html',varo="window.location = '/site';", year=datetime.datetime.now().year)
        return render_template('index.html',varo=render.hnslogin(), year=datetime.datetime.now().year)
    # Remove any ports
    host = request.host.split(':')[0]
    # Get content from site
    if os.path.isfile(f'sites/{host}.json'):
        with open(f'sites/{host}.json') as file:
            data = json.load(file)
        
        return render.site(data, host)
    return redirect(f'https://{DOMAINS[0]}')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/site')
def site():
    # Get auth domain
    if 'auth' not in request.cookies:
        return redirect('/')
    auth = request.cookies['auth']
    for i in cookies:
        if i['cookie'] == auth:
            # Load site content
            if os.path.isfile(f'sites/{i["name"]}.json'):
                with open(f'sites/{i["name"]}.json') as file:
                    data = json.load(file)
                    preview = render.preview(data)
            else:
                with open(f'sites/example.json') as file:
                    data = json.load(file)
                    preview = render.preview(data)
                    data = {
                        'title': '',
                        'link_0': '',
                        'link_1': '',
                        'link_2': '',
                        'link_3': '',
                        'link_0_url': '',
                        'link_1_url': '',
                        'link_2_url': '',
                        'link_3_url': '',
                        'image': '',
                        "bg_0": "#001665",
                        "bg_1": "#000000",
                        "fg_0": "#ffffff",
                        "btn_bg": "#2c54cf",
                        "btn_fg": "#ffffff",
                        "socials": [],
                        "address": [],
                        "nostrs": []
                    }


            title = data['title']
            link_0 = data['link_0']
            link_1 = data['link_1']
            link_2 = data['link_2']
            link_3 = data['link_3']
            link_0_url = data['link_0_url']
            link_1_url = data['link_1_url']
            link_2_url = data['link_2_url']
            link_3_url = data['link_3_url']
            fg_0 = data['fg_0']
            bg_0 = data['bg_0']
            bg_1 = data['bg_1']
            btn_bg = data['btn_bg']
            btn_fg = data['btn_fg']
            socials = data['socials']
            address = data['address']

            # Convert socials to dict
            socials = {i['name']: i['url'] for i in socials}
            address = {i['token']: i['address'] for i in address}
            tlsa = data['tlsa'] if 'tlsa' in data else ''
            ip = IP

            return render_template('site.html', year=datetime.datetime.now().year, domain=i['name'],
            title=title, link_0=link_0, link_1=link_1, link_2=link_2, link_3=link_3,
            link_0_url=link_0_url, link_1_url=link_1_url, link_2_url=link_2_url,
            link_3_url=link_3_url, fg_0=fg_0, bg_0=bg_0, bg_1=bg_1, btn_bg=btn_bg, btn_fg=btn_fg,
            socials=socials,address=address,preview=preview,tlsa=tlsa,ip=ip)
    response = make_response(redirect('/'))
    response.set_cookie('auth', '', expires=0)
    return response

@app.route('/site', methods=['POST'])
def site_post():
    if 'auth' not in request.cookies:
        return redirect('/')
    auth = request.cookies['auth']

    for i in cookies:
        if i['cookie'] == auth:
            # Get site content
            if os.path.isfile(f'sites/{i["name"]}.json'):
                with open(f'sites/{i["name"]}.json') as file:
                    data = json.load(file)
            else:
                with open(f'sites/example.json') as file:
                    data = {}


            # Save site content
            data['title'] = request.form['title']
            data['link_0'] = request.form['link_0']
            data['link_1'] = request.form['link_1']
            data['link_2'] = request.form['link_2']
            data['link_3'] = request.form['link_3']
            data['link_0_url'] = request.form['link_0_url']
            data['link_1_url'] = request.form['link_1_url']
            data['link_2_url'] = request.form['link_2_url']
            data['link_3_url'] = request.form['link_3_url']
            data['bg_0'] = request.form['bg_0']
            data['bg_1'] = request.form['bg_1']
            data['fg_0'] = request.form['fg_0']
            data['btn_bg'] = request.form['btn_bg']
            data['btn_fg'] = request.form['btn_fg']
            if 'image' not in data:
                data['image'] = ''

            socials = []
            socials.append({'name': 'email', 'url': request.form['email']})
            socials.append({'name': 'twitter', 'url': request.form['twitter']})
            socials.append({'name': 'github', 'url': request.form['github']})
            socials.append({'name': 'youtube', 'url': request.form['youtube']})

            address = []
            address.append({'token': 'hns', 'address': request.form['hns']})
            address.append({'token': 'eth', 'address': request.form['eth']})
            address.append({'token': 'btc', 'address': request.form['btc']})
            address.append({'token': 'sol', 'address': request.form['sol']})

            # Remove empty socials and addresses
            socials = [social for social in socials if social['url'] != '']
            # Make sure links all start with http or https
            for social in socials:
                # Set link to lowercase
                social['url'] = social['url'].lower()
                if not social['url'].startswith('http') and social['name'] != 'email':
                    social['url'] = 'https://' + social['url']


            data['socials'] = socials
            address = [i for i in address if i['address'] != '']
            data['address'] = address

            if 'image' in request.files:
                if request.files['image'].filename != '' and request.files['image'].filename != None:
                # Make sure the file is an image
                    file = request.files['image']
                    extension = file.filename.split('.')[-1]

                    file.save(f'avatars/{i["name"]}.' + extension)
                    data['image'] = f'{i["name"]}.' + extension               
                    

            with open(f'sites/{i["name"]}.json', 'w') as file:
                json.dump(data, file)
            return redirect('/site')
        
    response = make_response(redirect('/'))
    response.set_cookie('auth', '', expires=0)
    return response

@app.route('/image/delete')
def delete_image():
    if 'auth' not in request.cookies:
        return redirect('/')
    auth = request.cookies['auth']

    for i in cookies:
        if i['cookie'] == auth:
            # Get site content
            if os.path.isfile(f'sites/{i["name"]}.json'):
                with open(f'sites/{i["name"]}.json') as file:
                    data = json.load(file)
                    if 'image' in data:
                        data['image'] = ''
                        with open(f'sites/{i["name"]}.json', 'w') as file:
                            json.dump(data, file)
            return redirect('/site')
                
    response = make_response(redirect('/'))
    response.set_cookie('auth', '', expires=0)
    return response

@app.route('/preview')
def site_preview():
    if 'auth' not in request.cookies:
        return redirect('/')
    auth = request.cookies['auth']

    for i in cookies:
        if i['cookie'] == auth:
            # Load site content
            if os.path.isfile(f'sites/{i["name"]}.json'):
                with open(f'sites/{i["name"]}.json') as file:
                    data = json.load(file)                    
            else:
                with open(f'sites/example.json') as file:
                    data = json.load(file)
            return render.site(data)
                
    response = make_response(redirect('/'))
    response.set_cookie('auth', '', expires=0)
    return response

@app.route('/publish')
def publish():
    if 'auth' not in request.cookies:
        return redirect('/')
    auth = request.cookies['auth']

    for i in cookies:
        if i['cookie'] == auth:
            # Load site content
            if os.path.isfile(f'sites/{i["name"]}.json'):
                with open(f'sites/{i["name"]}.json') as file:
                    data = json.load(file)
                    if 'tlsa' in data:
                        # Site is already published
                        return redirect('/site')
                    def generate_ssl_and_write_nginx():
                        tlsa = nginx.generate_ssl(i['name'])
                        data['tlsa'] = tlsa
                        with open(f'sites/{i["name"]}.json', 'w') as file:
                            json.dump(data, file)
                        nginx.write_nginx_conf(i['name'])

                    threading.Thread(target=generate_ssl_and_write_nginx).start()
                    return redirect('/publishing')


                    
    response = make_response(redirect('/'))
    response.set_cookie('auth', '', expires=0)
    return response

@app.route('/nostr')
def nostr():
    if 'auth' not in request.cookies:
        return redirect('/')
    auth = request.cookies['auth']

    for i in cookies:
        if i['cookie'] == auth:
            # Load site content
            if os.path.isfile(f'sites/{i["name"]}.json'):
                with open(f'sites/{i["name"]}.json') as file:
                    data = json.load(file)
                    nostr = []
                    if 'nostr' in data:
                        nostr = data['nostr']
                    
                    return render_template('nostr.html',year=datetime.datetime.now().year, domain=i['name'],nostr=nostr)
                    
    response = make_response(redirect('/'))
    response.set_cookie('auth', '', expires=0)
    return response

@app.route('/nostr', methods=['POST'])
def nostr_post():
    if 'auth' not in request.cookies:
        return redirect('/')
    auth = request.cookies['auth']

    for i in cookies:
        if i['cookie'] == auth:
            # Get site content
            if os.path.isfile(f'sites/{i["name"]}.json'):
                with open(f'sites/{i["name"]}.json') as file:
                    data = json.load(file)
            else:
                return redirect('/site')

            nostr = []
            if 'nostr' in data:
                nostr = data['nostr']
            
            # Check for new nostr links
            if 'new-name' in request.form and 'new-pub' in request.form:
                name = request.form['new-name']
                pub = request.form['new-pub']
                id = len(nostr)
                for link in nostr:
                    if link['name'] == name:
                        link['pub'] = pub
                        data['nostr'] = nostr
                        with open(f'sites/{i["name"]}.json', 'w') as file:
                            json.dump(data, file)
                        return redirect('/nostr')
                    if link['id'] >= id:
                        id = link['id'] + 1

                nostr.append({'name': name, 'pub': pub, 'id': id})
            

            data['nostr'] = nostr
            with open(f'sites/{i["name"]}.json', 'w') as file:
                json.dump(data, file)
            return redirect('/nostr')
        
    response = make_response(redirect('/'))
    response.set_cookie('auth', '', expires=0)
    return response

@app.route('/nostr/delete/<int:id>')
def nostr_delete(id):
    if 'auth' not in request.cookies:
        return redirect('/')
    auth = request.cookies['auth']

    for i in cookies:
        if i['cookie'] == auth:
            # Get site content
            if os.path.isfile(f'sites/{i["name"]}.json'):
                with open(f'sites/{i["name"]}.json') as file:
                    data = json.load(file)
            else:
                return redirect('/site')

            nostr = []
            if 'nostr' in data:
                nostr = data['nostr']
            
            nostr = [i for i in nostr if i['id'] != id]
            data['nostr'] = nostr
            with open(f'sites/{i["name"]}.json', 'w') as file:
                json.dump(data, file)
            return redirect('/nostr')
        
    response = make_response(redirect('/'))
    response.set_cookie('auth', '', expires=0)
    return response


@app.route('/.well-known/wallets/<path:path>')
def wallets(path):
    # Check if host is in domains
    if request.host in DOMAINS:
        # Check if user is logged in
        if 'auth' not in request.cookies:
            return redirect(f'https://{DOMAINS[0]}')
        auth = request.cookies['auth']
        for i in cookies:
            if i['cookie'] == auth:
                # Load site content
                if os.path.isfile(f'sites/{i["name"]}.json'):
                    with open(f'sites/{i["name"]}.json') as file:
                        data = json.load(file)
                    for i in data['address']:
                        if i['token'].upper() == path:
                            # Return as plain text
                            response = make_response(i['address'])
                            response.headers['Content-Type'] = 'text/plain'
                            return response

    # Get wallet from domain
    host = request.host.split(':')[0]

    if os.path.isfile(f'sites/{host}.json'):
        with open(f'sites/{host}.json') as file:
            data = json.load(file)
        for i in data['address']:
            if i['token'].upper() == path:
                # Return as plain text
                response = make_response(i['address'])
                response.headers['Content-Type'] = 'text/plain'
                return response
    return render_template('404.html', year=datetime.datetime.now().year), 404

@app.route('/.well-known/nostr.json')
def nostr_account():
    # Check if host is in domains
    if request.host in DOMAINS:
        # Check if user is logged in
        if 'auth' not in request.cookies:
            return redirect(f'https://{DOMAINS[0]}')
        auth = request.cookies['auth']
        for i in cookies:
            if i['cookie'] == auth:
                # Load site content
                if os.path.isfile(f'sites/{i["name"]}.json'):
                    with open(f'sites/{i["name"]}.json') as file:
                        data = json.load(file)
                    if 'nostr' in data:
                        nostr = data['nostr']
                        # Return as plain text
                        response = make_response(nostr_module.json(nostr))
                        response.headers['Content-Type'] = 'text/plain'
                        response.headers.add('Access-Control-Allow-Origin', '*')
                        return response

    # Get wallet from domain
    host = request.host.split(':')[0]

    if os.path.isfile(f'sites/{host}.json'):
        with open(f'sites/{host}.json') as file:
            data = json.load(file)
        if 'nostr' in data:
            nostr = data['nostr']
            # Return as plain text
            response = make_response(nostr_module.json(nostr))
            response.headers['Content-Type'] = 'text/plain'
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
    return render_template('404.html', year=datetime.datetime.now().year), 404
            

@app.route('/publishing')
def publishing():
    return render_template('publishing.html')

# region Auth
@app.route('/auth', methods=['POST'])
def auth():
    global cookies
    auth = login(request)
    if auth == False:
        return render_template('index.html',varo=render.varo_login(), year=datetime.datetime.now().year, error="Failed to login")
    resp = make_response(render_template_string("Success"))
    # Gen cookie
    auth_cookie = secrets.token_hex(12 // 2)
    cookies.append({'name': auth, 'cookie': auth_cookie})

    with open('cookies.json', 'w') as file:
        json.dump(cookies, file)

    resp.set_cookie('auth', auth_cookie)
    return resp

@app.route('/auth', methods=['GET'])
def auth_get():
    global cookies
    
    if 'username' not in request.args:
        return redirect('/?error=Failed to login&reason=No username')
    username = request.args['username']

    if 'token' not in request.args and 'signature' not in request.args:
        return redirect('/?error=Failed to login&reason=No token')
    
    if 'token' in request.args:
        token = request.args['token']
    
        # Check if user is valid
        r = requests.get(f'https://login.hns.au/auth/user?token={token}')
        if r.status_code != 200:
            print(r.text,flush=True)
            return redirect('/?error=Failed to login&reason=Failed to connect to HNS Login')
        try:
            r = r.json()
        except:
            print(r.text,flush=True)
            return redirect('/?error=Failed to login&reason=Failed to connect to HNS Login')

        if 'error' in r:
            return redirect('/?error=Failed to login&reason=' + r['error'])

        if r['username'] != username:
            return redirect('/?error=Failed to login&reason=Username mismatch')
    
    else: # Signature based login
        signature = request.args['signature']
        r = requests.post(f'http://x:{HSD_API}@{HSD_IP}:{HSD_PORT}', json={
            'method': 'verifymessagewithname',
            'params': [username, signature, "hns-links"]
        })
        if r.status_code != 200:
            return jsonify({'error': 'Failed to connect to HSD',"success":False}), 500
        r = r.json()
        if 'result' not in r:
            return jsonify({'error': 'Failed to verify signature',"success":False}), 400
        if r['result'] != True:
            return jsonify({'error': 'Failed to verify signature',"success":False}), 400

    auth_cookie = secrets.token_hex(12 // 2)
    cookies.append({'name': username, 'cookie': auth_cookie})

    with open('cookies.json', 'w') as file:
        json.dump(cookies, file)

    resp = make_response(redirect('/site'))
    resp.set_cookie('auth', auth_cookie)
    return resp

@app.route('/logout')
def logout():
    global cookies
    resp = make_response(redirect('/'))
    resp.set_cookie('auth', '', expires=0)

    if 'auth' not in request.cookies:
        return resp
    cookies = [i for i in cookies if i['cookie'] != request.cookies['auth']]
    with open('cookies.json', 'w') as file:
        json.dump(cookies, file)

    return resp

def login(request):
    dict = request.form.to_dict()
    keys = dict.keys()
    keys = list(keys)[0]
    keys = json.loads(keys)
    auth_request = keys['request']
    # return login(auth_request)
    r = requests.get(f'https://auth.varo.domains/verify/{auth_request}')
    r = r.json()
    if r['success'] == False:
        return False
    
    if 'data' in r:
        data = r['data']
        if 'name' in data:
            return data['name']
    return False

# endregion

@app.route('/avatar/<path:path>')
def avatar(path):
    return send_from_directory('avatars', path)

@app.route('/token/<path:path>')
def tokens(path):
    # Colour is last char
    colour = path[-1]
    token = path[:-1]
    if colour.lower() == 'w':
        return send_from_directory('templates/assets/img/tokens', f'{token}W.png')
    return send_from_directory('templates/assets/img/tokens', f'{token}.png')

# region API routes
@app.route('/api/v1/site', methods=['POST'])
def api_site_post():
    if not request.json:
        return jsonify({'error': 'No JSON data provided',"success":False}), 400
    if 'domain' not in request.json:
        return jsonify({'error': 'No domain provided',"success":False}), 400
    if 'signature' not in request.json:
        return jsonify({'error': 'No signature provided',"success":False}), 400
    if 'data' not in request.json:
        return jsonify({'error': 'No data provided',"success":False}), 400
    
    domain = request.json['domain']
    signature = request.json['signature']
    data = request.json['data']
    # Verify signature
    r = requests.post(f'http://x:{HSD_API}@{HSD_IP}:{HSD_PORT}', json={
        'method': 'verifymessagewithname',
        'params': [domain, signature, "hns-links"]
    })
    if r.status_code != 200:
        return jsonify({'error': 'Failed to connect to HSD',"success":False}), 500
    r = r.json()
    if 'result' not in r:
        return jsonify({'error': 'Failed to verify signature',"success":False}), 400
    if r['result'] != True:
        return jsonify({'error': 'Failed to verify signature',"success":False}), 400
    
    keys = ['title', 'link_0', 'link_1', 'link_2', 'link_3', 'link_0_url', 'link_1_url', 'link_2_url', 'link_3_url', 'fg_0', 'bg_0', 'bg_1', 'btn_bg', 'btn_fg', 'image']
    for key in keys:
        if key not in data:
            data[key] = ''

    if os.path.exists(f'sites/{domain}.json'):
        with open(f'sites/{domain}.json') as file:
            old_data = json.load(file)
            if 'tlsa' in old_data:
                data['tlsa'] = old_data['tlsa']
            for key in old_data:
                if key not in data:
                    data[key] = old_data[key]
                if data[key] == '':
                    data[key] = old_data[key]

    if 'socials' not in data:
        data['socials'] = []
    if 'address' not in data:
        data['address'] = []

    with open(f'sites/{domain}.json', 'w') as file:
        json.dump(data, file)

    if 'tlsa' in data:
        return jsonify({'error': None, "success":True,"TLSA": data['tlsa'],"IP":IP}), 200
    def generate_ssl_and_write_nginx():
        tlsa = nginx.generate_ssl(domain)
        data['tlsa'] = tlsa
        with open(f'sites/{domain}.json', 'w') as file:
            json.dump(data, file)
        nginx.write_nginx_conf(domain)

    threading.Thread(target=generate_ssl_and_write_nginx).start()

    return jsonify({'error': None, "success":True,"TLSA":None,"IP":IP}), 200

@app.route('/api/v1/site', methods=['GET'])
def api_site_get():
    if 'domain' not in request.args:
        return jsonify({'error': 'No domain provided',"success":False}), 400
    domain = request.args['domain']
    if os.path.exists(f'sites/{domain}.json'):
        with open(f'sites/{domain}.json') as file:
            data = json.load(file)
            return jsonify({'error': None, "success":True,"data":data,"IP":IP}), 200
    return jsonify({'error': 'Site not found',"success":False}), 404


# endregion



# 404 catch all
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', year=datetime.datetime.now().year), 404


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')