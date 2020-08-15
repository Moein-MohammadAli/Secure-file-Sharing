# Share Files Securely
In this project we tried to create a place that can be used to share files securely. We used django-rest-framework in order to create needed APIs.
First let's start by running the project then we will check what options do we have and what security mechanisms are implemented.

## Requirements
All we need is virtualenv and python 3.7 to get started. Other requirements are put in requirements.txt file and we can use **pip** to install them. 
Here is a list of them
* django>=2.2,<2.3
* djangorestframework>=3.10,<3.11
* pycryptodome==3.9.8
* requests
* sentry-sdk==0.16.2
* raven==6.10.0

### Run

```
virtualenv -p python3.7 venv
source /venv/bin/activate
pip install -r requirements.txt
python manage.py makemigrations
python manane.py migrate
python manage.py runserver

```

***\*** Note that we need to have python3.7 installed before we try for creating virtual environment*

After running above commands, server is running. But we can use **docker**, too. just replace container_name wit 
```
docker build -t nginxt .

docker-compose logs -f

```

## APIs

* register/
  * New user registeration

* login/
  * login user
* put/
  * upload a file to server
* list/
  * list all items uploaded by any user on the server
* read/
  * user read content of his/her files
* write/
  * user overwrites to his/her files 
* get/
  * user download his/her files from server and specified file will get removed
* chmod/
  * give access to specific user

Following list shows how to use these APIs:

    * register <username> <password> <conf. label> <integrity label>
    * login <username> <password>
    * put <filename> <conf.label> <integrity label>
    * read <filename>
    * write <filename> <content>
    * get <filename>
    * chmod <access> <username> <filename>

***\*** Also there is [client](https://github.com/Secure-File-Sharing/Client) side which all of theses functionalities are implemented there*

## Mechanisms
Serveral security techniques are considered it are briefly menthoned at the following:
* Auditing
Using sentry-sdk package all of the events happened in the system is recorded

* Cryptography
First client create a session key which has length of 128 bits. Then, AES algorithm encrypts/decrypts all data passing between server and client using key 
with length 128 bits. Server's public key should be hardcoded in client's app, in order to share session's key between server and client. 
Using RSA algorithm, session key get transfered to server.

* BLP model
This model is used for access control when confidentiality of data is important.

* Biba
This model is used for access control when integrity of data is important.

***When a user tries to upload a file, he/she shouldn't violate his/her access according to BLP and Biba model. Otherwise, since there will be security issues
upload won't get completed. These two models are considered when a user tries to read a file alongside discretionary access control***

* Discretionary access control
We have three types of access:
  * Write
    user can overwrite content of a file
  * Read
    user can read content of a file
  * Get
    user can download a file from server and remove it. *This access is highest possible access in this system"

* OS command injection and Path traversal
These two threats are handled by using hash of the file name instead of using file name given by user directly.

