# coding=utf-8
import requests
import sys


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


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
            'delete': BASE_URL + "document/"
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
                # print "status:" + str(download_request.status_code)
                pass
            return download_request

        except requests.RequestException as e:
            print e
            sys.exit(1)

    def delegate(self):
        # TODO Implement delegate function
        pass

    def delete(self, document_id):
        try:
            delete_request = self.session.delete(url=self.URLS['delete'] + str(document_id), cert=(self.cert, self.key), verify=False)
            return delete_request
        except requests.RequestException as e:
            print e
            sys.exit(1)

    def logout(self):
        try:
            logout_request = self.session.post(self.URLS['logout'], cert=(self.cert, self.key), verify=False)
            return logout_request
        except requests.RequestException as e:
            print e
            sys.exit(1)

# Place holders for the different test scenarios we have to run.


def printOut(test_num, status, message=""):
    if status is "ERROR":
        print bcolors.OKBLUE + "[Test " + str(test_num) + "] " + bcolors.ENDC + bcolors.FAIL + "[**ERROR**] " + bcolors.ENDC + message
    if status is "SUCCESS":
        print bcolors.OKBLUE + "[Test " + str(test_num) + "] " + bcolors.ENDC + bcolors.OKGREEN + "[SUCCESS]" + bcolors.ENDC
    if status is "FAILED":
        print bcolors.OKBLUE + "[Test " + str(test_num) + "] " + bcolors.ENDC + bcolors.FAIL + "[FAILED] " + bcolors.ENDC
    if status is "LOG":
        print bcolors.OKBLUE + "[Test " + str(test_num) + "] " + bcolors.ENDC + message
    if status is "HEADER":
        print bcolors.HEADER + "\n[Test " + str(test_num) + "]" + bcolors.ENDC


def test1(client_0):
    """
    Test Case: Checking-in with INTEGRITY security flag
        -Initialize session as client_0
        -Check in document "0.txt" with INTEGRITY flag
        -Show where the checked-in document and its signature will be located on the server
        -Cant really show this here, will include in README
    :returns: checkin result
    """
    printOut(1, "HEADER")
    printOut(1, "LOG", "Attempting to initialize session for client_0")
    client_0.login()
    printOut(1, "LOG", "Session initialized as client_0")
    printOut(1, "LOG", "Attempting to check in document '0.txt' with INTEGRITY flag set")
    request = client_0.upload('files/0.txt', '0.txt', 'INTEGRITY')

    if request.status_code == 201:
        result = True
        printOut(1, "LOG", "Upload of '0.txt' is successful")
        return result, client_0
    else:
        result = False
        printOut(1, "ERROR", "Upload of '0.txt' failed")
        return result, client_0


def test2(client_0):
    """
    Test Case: Checking-out a document as its owner
        -Using the same session, check out the document we just uploaded
        -Store retrieved file as 0_copy.txt
    :returns checkout result
    """
    printOut(2, "HEADER")
    printOut(2, "LOG", "Attempting to download 0.txt as 0_copy.txt")
    request = client_0.download('0.txt', "files/0_copy.txt")
    if request.status_code is 200:
        printOut(2, "LOG", "Download of '0_copy.txt' successful")
        result = True
    else:
        printOut(2, "ERROR", "Download of '0_copy.txt' failed")
        result = False
    return result


def test3(client_1):
    """
    Test Case: Checking-out a document as a user without access permission
        -Initialize a session with the server as the second client (client_1) and check
         out the document "0.txt" and attempt to store it as "0_copy.txt"
        -This should fail
    :returns: checkout result
    """
    printOut(3, "HEADER")
    printOut(3, "log", "Attempting to initialize session for client_1")
    client_1.login()
    printOut(3, "LOG", "Session initialized as client_1")
    printOut(3, "LOG", "Attempting to download 0.txt as client_1")
    request = client_1.download("0.txt", "files1/0_copy.txt")
    if request.status_code == 200:
        print "[Test 3] Download of 0.txt as 0_copy.txt successful"
        result = True
    else:
        printOut(3, "ERROR", "[Insufficient Permissions] Download of 0.txt failed")
        result = False

    return result


def test4(client_0):
    """
    Test Case: Safe Deletion
        -Using the first session, safely delete "0.txt"
        -Then attempt to check it out again and store as "0_copy2.txt
    :returns: delete result, checkout result
    """
    printOut(4, "HEADER")
    printOut(4, "LOG", "Attempting to delete '0.txt' as client_0")
    request = client_0.delete("0.txt")
    if request.status_code == 200:
        printOut(4, "LOG", "Secure deletion of '0.txt' successful")
    else:
        printOut(4, "ERROR", "Secure delection of '0.txt' failed")
        return False
    request = client_0.download("0.txt", "files/0_copy2.txt")
    if request.status_code == 200:
        printOut(4, "LOG", "Download of 0.txt is successful")
    else:
        printOut(4, "ERROR", "Download of 0.txt failed, status code: "+ str(request.status_code))
        return False
    return True

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

# Conducting test 1
client_0 = Client('certs/s2drClient0.cert.pem', 'keys/s2drClient0.key.pem')
test1_result, client_0 = test1(client_0)
if test1_result is True:
    printOut(1, "SUCCESS")
else:
    printOut(1, "FAILED")

# Conducting test 2
test2_result = test2(client_0)
if test2_result is True:
    printOut(2, "SUCCESS")
else:
    printOut(2, "FAILED")

# Conducting test 3
client_1 =Client('certs/s2drClient1.cert.pem', 'keys/s2drClient1.key.pem')
test3_result = test3(client_1)
if test3_result is True:
    printOut(3, "SUCCESS")
else:
    printOut(3, "FAILED")

# Conducting test 4
test4_result = test4(client_0)
if test4_result is True:
    printOut(4, "SUCCESS")
else:
    printOut(4, "FAILED")

# TODO: Make sure to logout clients as the test cases dictate
client_0.logout()

# mike = Client('certs/s2drClient2.cert.pem', 'keys/s2drClient2.key.pem')
# mike.login()
# mike.upload('files/test2.txt', 'test2.txt', 'NONE')
# mike.download('test2.txt', 'downloads/test2_copy.txt')
# mike.logout()
