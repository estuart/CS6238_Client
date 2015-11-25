import requests
import json
import datetime
import sys

def print_response(*args):
    # For successful API call, response code will be 200 (OK)
    for response in args:
        print "Content" + str(response.content)
        if response.ok:
            print "HERE"
            # Loading the response data into a dict variable
            # json.loads takes in only binary or string variables so using content to fetch binary content
            # Takes a Json file and converts into python data structure (dict or list, depending on JSON)
            if response.content:
                print response.status_code
                j_data = json.loads(response.content)
                for key in j_data:
                    print key + " : " + j_data[key]
            else:
                print response.status_code
                print "<No Content>"
        else:
            # If response code is not ok (200), print the resulting http error code with description
            response.raise_for_status()


def login(username, password, session):
    _s = session
    try:
        login_request = _s.post(url=urls['login'], files=dict(username='estuart', password='password'), verify=False)
        return login_request

    except requests.RequestException as e:
        print e
        sys.exit(1)


def upload(filepath, filename, security_flag, session):
    _s = session
    try:
        # Create a dict with the upload parameters as key value pairs
        _files = {'document': open(filepath, 'rb'), "documentName": filename, "securityFlag": security_flag}
        # I pass a files dict as a way to force request lib to send form-data instead of www-encoded-form data
        upload_request = _s.post(url=urls['upload'], files=_files, verify=False)

        return upload_request

    except requests.RequestException as e:
        print e
        sys.exit(1)


def download(document_id, session):
    _s = session
    try:
        download_request = _s.get(url=urls['download'] + str(document_id), stream=True, verify=False)
        if download_request.status_code == 200:
            try:
                with open("download_" + str(datetime.datetime.now()), 'wb') as f:
                    for chunk in download_request:
                        f.write(chunk)
            except (IOError, requests.RequestException) as e:
                print "I/O error({0}): {1}".format(e.errno, e.strerror)
        else:
            print "status:" + str(download_request.status_code)

        return download_request

    except requests.RequestException as e:
        print e
        sys.exit(1)


def logout(session):
    _s = session
    try:
        logout_request = _s.post(urls['logout'], verify=False)
        return logout_request
    except requests.RequestException as e:
        print e
        sys.exit(1)

# Root url of our API
# url = http://52.22.45.83
#BASE_URL = "http://localhost:8080/s2dr/"
BASE_URL = "https://localhost:8443/s2dr/"
urls = {'login': BASE_URL + "login",
        'personal': BASE_URL + "personal",
        'upload': BASE_URL + "upload/",
        'download': BASE_URL + "document/",
        'logout': BASE_URL + "logout/",
        }

# TODO: Add support for using our CA
# TODO: Remove this line after CA thing is figured out
requests.packages.urllib3.disable_warnings()

# Create a session object to handle our session.
s = requests.session()
#with requests.session() as s:
print urls['login']
# I pass a files dict as a way to force request libs to send form-data instaed www-encoded-form data

login = login("estuart", "password", s)
print "Login: "+str(login.status_code)
upload = upload("classNotes.rtf", "classNotes11", "NONE", s)
print "Upload: "+str(upload.status_code)
download = download(1, s)
print "download: "+str(download.status_code)
logout = logout(s)
print "logout: "+str(logout.status_code)


