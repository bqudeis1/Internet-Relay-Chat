#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <fstream>
#include <thread>

using namespace std;

void receiveMessage(int c_socket)
{
	char message[1024];
	while (true)
	{
		int readB = recv(c_socket, message, sizeof(message), 0);
		if (readB <= 0)
		{
			cerr << "CONNECTION CLOSED" << strerror(errno) << endl;
			break;
		}
		cout << string(message, readB) << endl;
	}
}

void sendMessage(int c_socket)
{
	string firstMessage = "CLIENT";
	send(c_socket, firstMessage.c_str(), firstMessage.length(), 0);
	while (true)
	{
		string message;
		getline(cin, message);
		if (send(c_socket, message.c_str(), message.length(), 0) == -1)
		{
			cerr << "faild to send msg" << strerror(errno) << endl;
			break;
		}
		if (message == "QUIT")
		{
			cout << "SIGNING OUT..." << endl;
			close(c_socket);
			exit(0);
		}
	}
}
void readClientConfig(string &serverIP, int &serverPort)
{
	ifstream clientConfig("client.conf");
	if (!clientConfig.is_open())
	{
		throw runtime_error("cant open client.conf or misstyped file name");
	}
	string line;
	while (getline(clientConfig, line))
	{
		if (line.find("SERVER_IP=") != string::npos)
		{
			serverIP = line.substr(line.find("=") + 1);
		}
		else if (line.find("SERVER_PORT=") != string::npos)
		{
			serverPort = stoi(line.substr(line.find("=") + 1));
		}
	}
	clientConfig.close();
}

int main(int argc, char *argv[])
{
	string server_ip = "192.168.1.16";
	string serverIP;
	int serverPort;
	readClientConfig(serverIP, serverPort);
	const int servPort = serverPort;
	int client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket == -1)
		throw runtime_error("faild to create socket");
	sockaddr_in server_address{};
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(servPort);
	server_address.sin_addr.s_addr = inet_addr(serverIP.c_str());
	if (connect(client_socket, (sockaddr *)&server_address, sizeof(server_address)) == -1)
		cerr << "couldnot connect to server" << strerror(errno) << endl;
	thread receive_thread(receiveMessage, client_socket);
	thread send_thread(sendMessage, client_socket);
	receive_thread.join();
	send_thread.join();

	return 0;
}