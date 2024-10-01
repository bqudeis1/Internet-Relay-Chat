# Internet Relay Chat Implementation using C++
based on RFC 2812 and 2813
## Configuration
requirments: c plus plus 17 or above, port number for servers must be > 9000.

Before running the program, ensure the following steps are completed:

1. On the server machine, open a terminal and type "hostname -I" to retrieve the IP address of the server.
2. Copy the IP address obtained from step 1 and paste it into the "client.conf" file in the "SERVER_IP" attribute.
3. Save and close the "client.conf" file.

## Usage
To run the IRC console application, follow these steps:

1. On the server machine, open a terminal and navigate to the project directory.
2. Run `make` to compile the server and the client code.
3. Start the server by running "./server".
4. I will provide 2 folders, one folder for each machine to act as a server.


On the client side machine:

1. Open a terminal and navigate to the project directory.
2. Run "make" to compile the code. If you are using the same machine please ignore this step.
3. Start the client program by running "./client".

## Acknowledgments
This project was implemented by Baha' Qudeisat under the supervision of Professor Dali Ismail.

please contact me at bqudies1@binghamton.edu for any questions or feedback
