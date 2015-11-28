# coding=utf-8
import requests
import sys


class Client:
    # Root url of our API
    # url = http://52.22.45.83
    # BASE_URL = "http://localhost:8080/s2dr/"
    BASE_URL = "https://localhost:8443/s2dr/"

    URLS = {'login': BASE_URL + "login",
            'personal': BASE_URL + "personal",
            'upload': BASE_URL + "upload/",
            'download': BASE_URL + "document/",
            'logout': BASE_URL + "logout/",
            }

    def __init__(self, cert, key):
        self.session = requests.Session()
        # TODO Remove this once certs are figured out
        self.cert = cert
        self.key = key

    def __str__(self):
        return 'Client={0}, Cert={1}, Key={2}'.format(self.session, self.cert, self.key)

    def login(self):
        try:
            login_request = self.session.post(url=self.URLS['login'], cert=(self.cert, self.key), verify=False)
            return login_request
        except requests.RequestException as e:
            print e
            sys.exit(1)

    def upload(self, file_path, filename, security_flag):
        try:
            # Create a dict with the upload parameters as key value pairs
            _files = {'document': open(file_path, 'rb'), "documentName": filename, "securityFlag": security_flag}
            # I pass a files dict as a way to force request lib to send form-data instead of www-encoded-form data
            upload_request = self.session.post(url=self.URLS['upload'], files=_files, cert=(self.cert, self.key), verify=False)
            return upload_request
        except requests.RequestException as e:
            print e
            sys.exit(1)

    def download(self, document_id, filename):
        try:
            download_request = self.session.get(url=self.URLS['download'] + str(document_id), stream=True, cert=(self.cert, self.key), verify=False)
            if download_request.status_code == 200:
                try:
                    with open(str(filename), 'wb') as f:
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

    def delegate(self):
        # TODO Implement delegate function
        pass

    def logout(self):
        try:
            logout_request = self.session.post(self.URLS['logout'], cert=(self.cert, self.key), verify=False)
            return logout_request
        except requests.RequestException as e:
            print e
            sys.exit(1)

# Place holders for the different test scenarios we have to run.


def test1():
    """
    Test Case: Checking-in with INTEGRITY security flag
        -Initialize session as client_0
        -Check in document "0.txt" with INTEGRITY flag
        -Show where the checked-in document and its signature will be located on the server
        -Cant really show this here, will include in README
    :returns: checkin result
    """
    pass


def test2():
    """
    Test Case: Checking-out a document as its owner
        -Using the same session, check out the document we just uploaded
        -Store retrieved file as 0_copy.txt
    :returns checkout result
    """
    pass


def test3():
    """
    Test Case: Checking-out a document as a user without access permission
        -Initialize a session with the server as the second client (client_1) and check
         out the document "0.txt" and attempt to store it as "0_copy.txt"
        -This should fail
    :returns: checkout result
    """
    pass


def test4():
    """
    Test Case: Safe Deletion
        -Using the first session, safely delete "0.txt"
        -Then attempt to check it out again and store as "0_copy2.txt
    :returns: delete result, checkout result
    """
    pass


def test5():
    """
    Test Case: Checking-in and Checking-out with CONFIDENTIALITY security flag
        -Using the first session, check in a second document "1.txt" with CONFIDENTIALITY
        -In readme show where the server copy of "1.txt" is located (needs to be encrypted)
        -Using same session check out second document and store as "1_copy.txt"
        -Terminate the first session
    :returns: checkin result, checkout result, session termination result
    """
    pass


def test6():
    """
    Test Case: Updating a Document
        -Restart the first session
        -Checkin the second document "1.txt" with CONFIDENTIALITY|INTEGRITY flag
        -Verify the signature of the encrypted copy
        -Checkout "1.txt" and store it as "1_copy2.txt"
    :returns: checkin result, verify result, checkout result
    """
    pass


def test7():
    """
    Test Case: Checking-in & Checking-out delegation without propogation
        -Using the first session, delegate("1.txt", "client_1",30,checking-in|checking-out, false)
        -Using the second session(client 1) checkout "1.txt" and store it as "1_copy.txt"
        -Using the second session, check in a different file as "1.txt"
        -Using the second session, delegate("1.txt", "client_2", 30, checking-in|checking-out, false)
        -Initialize a session as the third client (client_2) checkout the document"1.txt" and store it as "1_copy.txt"
        -After the delegation expires, using the second session (client_1), check out "1.txt"
         and store it as "1_copy2.txt"
        -Using the first session, check out "1.txt" and store it as "1_copy3.txt"
    :return:
    """
    pass


def test8():
    """
    Test Case: Checking-out delegation with propogation
        -Using the first session, delegate(“1.txt”, “client_1”, 30, checking-out, True). The delegation timeout should
         be 30 seconds.
        -Using the second session, delegate(“1.txt”, “client_2”, 60, checking-out, False). The delegation
         timeout should be 60 seconds.
        -Using the third session (client_2), check out “1.txt” and store it as “1_copy2.txt”.
        -After the 30-second delegation made by the owner expires, using the third session (client_2),
         check out “1.txt” and store it as “1_copy3.txt”.
        -After the 60-second delegation made by the second client expires, using the third session (client_2),
         check out “1.txt” and store it as “1_copy4.txt”.
        -Terminate all sessions

    :return:
    """
    pass

# TODO: Add support for using our CA
# TODO: Remove this line after CA thing is figured out
# This silences annoying SSL warning for using a self signed cert
requests.packages.urllib3.disable_warnings()


evan = Client('certs/s2drClient1.cert.pem', 'keys/s2drClient1.key.pem')
evan.login()
evan.upload('files/test1.txt', 'testing1.txt', 'NONE')
evan.download("testing1.txt", 'downloads/test1_copy.txt')
evan.logout()

mike = Client('certs/s2drClient2.cert.pem', 'keys/s2drClient2.key.pem')
mike.login()
mike.upload('files/test2.txt', 'test2.txt', 'NONE')
mike.download('test2.txt', 'downloads/test2_copy.txt')
mike.logout()
