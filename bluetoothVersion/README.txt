Secure Bluetooth Remote File Storage System
CSC 579 - HW3
Peter DeAngelis
William Vukasovic


*** Overview ***
This project is a two node (client-server) implementation of a secure remote file storage system. 
All communications between the client and server are encrypted at all times and files that are stored
on the remote server (e.g., after a file upload from the client) are also stored in a manner to ensure 
confidentiality and integrity.


*** Table of Contents ***
1) Application Technologies and Dependencies
2) How to Run the Application
3) User Instructions


**********************************************************
***      Application Technologies and Dependencies     ***
**********************************************************


The project is implemented with:
1) Python 3
2) PyCrypto 2.6.1 (for cryptography functions)
3) PyBluez 0.22 (for bluetooth communications between client and server)


The project was coded and tested with the client and server running on two raspberry PI devices, each running
the Raspbian OS. (Some developer testing was also carried out with the server running on a Windows10 laptop and
 a client running on a PI, so other non-Raspbian platforms can be supported, if the required version of python 
and libraries are installed.)


*** Application Dependencies ***
To run the program, first install all dependencies:
1) Ensure that python3 is installed.
2) Install the PyCrypto library: pip3 install pycrypto
3) Install PyBluez library: pip3 install pybluez
        i) This library has other dependencies which might need to be install first for this library’s installation to be successful.


**********************************************************
***            How to Run the Application              ***
**********************************************************


*** The application consists of four files ***:
1) cilentFile.py
2) serverFile.py
3) protocolConstants.py
        a) this is a constants file containing protocol commands. Both client and server depend on this file.
4) cryptoutil.py
        b) this is a utility file with helper methods for carrying out various cryptographic methods. 
	The server and client both use this file to perform cryptography functions. These utility methods depend on the pycrypo library.


*** To run the server ***:
1) Make sure serverFile.py is in the same directory as the protocolConstants and cryptoutil python files.
2) Execute the python file with this command: python3 serverFile.py


Note: during startup, the server will look for a “users” file in its root directory. This file is encrypted 
and contains the usernames and hashed passwords of three “seeded” users. If the file is not detected at startup, 
the server will create it, and continue startup as normal.


        Seeded Users and Passwords:
        1) peter - pwd1
        2) will - 1234
        3) profkim - security


*** To run the client ***:
1) Make sure clientFile.py is in the same directory as the protocolConstants and cryptoutil python files.
2) Open the clientFile.py and change the hardcoded bluetooth address at the top of the file. This address is 
the bluetooth address of the remote server that the client wants to connect too. Change the value to the server’s 
bluetooth address and save the file.
3) Execute the python file with this command: python3 clientFile.py


**********************************************************
***                 User Instructions.                 ***
**********************************************************
1) After starting the client, it will establish a connection to the server and begin the secure handshake process.
2) At the end of the handshake, the user will be prompted to enter a username and password (plaintext). 
One of the three seeded users above can be used.
3) After successful authentication, the user has established a secure session. In a secure session, a user is 
prompted to enter a command. They have three possible commands:
        i) PUT - for file upload
        ii) GET - for file download
        iii) BYE - to exit the application
4) If a user executes a PUT or GET, they will be prompted with instructions for the name of the file they want to 
upload or download. After entering the filename, the operation will be executed.
5) After an operation is performed, a user can issue another command or exit the client.


Special Note:
        i) For a file upload, if the user enters the name “myFileToUpload.txt”, the application will look for this 
	file in the application’s working directory.
        ii) When a file is successfully uploaded to the server, it will not be stored with a plaintext name
	(“myFileToUpload.txt”), but instead will have a “masked” name that is produced using an HMAC where the 
	key used in the hash is a user specific key.
        iii) To retrieve a file, even though it is stored on the server with a masked name, the user should still 
	request the file with its plaintext name (e.g.,“myFileToUpload.txt”) and the server will find and return the
	 appropriate file.