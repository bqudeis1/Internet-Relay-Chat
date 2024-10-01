#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <ctime>
#include <unordered_map>
#include <set>
#include <thread>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <mutex>
#include <map>
#include <string.h>
#include <limits.h>
#include <atomic>
#include <sys/socket.h>
#include <filesystem>
using namespace std;
class Client;
class ChannelManager;
class ClientManager;
class ServerConnection;
void setNumericReplies();
void read_usr_pass(string fileName);
bool inClientCommadSet(string command);
vector<string> split(const string &s, char delim);
string base64_decode(const string &in);
string base64_encode(const string &in);
string clientDataFileName = "hiddenPasswordFile.usr_pass";
mutex clients_mutex;
vector<Client *> clients;
vector<thread> threads;
map<int, string> numericReplies;
constexpr int PORT = 8080;
int port_num;
string s_nickname;
string s_pass;
string Host_Name;
string serverTime;
set<string> ClientCommandSet;
set<string> serverCommandSet;
map<string, string> decodePass;
map<string, string> serversIp;
map<int, ServerConnection> serversInfo;

void CurrentServerTimeAsString();
void setCommandSet();
void setServerCommandSet();
bool inServerCommadSet(string command);
class ServerConnection
{
	bool isAlive = true;

public:
	ServerConnection() {}
	ServerConnection(int server_socket)
	{
		this->server_socket = server_socket;
		handelServerRequest();
	}
	bool isAuthenticated = false;
	string pass;
	string IP;
	int port;
	int server_socket;
	int out;
	string nickName;
	bool passCommand(vector<string> params);
	void sendToServer(string message);
	void JoinCommand(string message);
	string getUsersNickNamesMessage();
	string getNJoinMessage();
	void handelServerRequest()
	{
		try
		{
			while (isAlive)
			{
				string message = readMessageFromSockt();
				cout << message << endl;
				proccesRequest(message);
				message = "";
			}
		}
		catch (exception e)
		{
			cout << e.what() << endl;
		}
		close(this->server_socket);
	}
	string readMessageFromSockt()
	{
		char message[1024];
		int bytes_read = recv(this->server_socket, message, sizeof(message), 0);
		if (bytes_read <= 0)
			isAlive = false;
		message[bytes_read] = '\0';
		string res = string(message);
		memset(message, 0, sizeof(message));
		return res;
	}
	void proccesRequest(string message)
	{
		vector<string> params = split(message, ' ');
		if (!inServerCommadSet(params[0]))
		{
			sendToServer("unknow command");
			return;
		}
		if (params[0] == "PASS")
		{
			this->passCommand(params);
		}
		else if (params[0] == "OK")
		{
			this->isAuthenticated = true;
		}
		else
		{
			if (isAuthenticated)
			{
				if (params[0] == "NJOIN")
				{
					sendToServer(getNJoinMessage());
				}
				else if (params[0] == "JOIN")
				{
					// sendToServer(getNJoinMessage());
				}
				else if (params[0] == "NickNames")
				{
					sendToServer(getUsersNickNamesMessage());
				}
				else if (params[0] == "NickNames:")
				{
					proccesNickNamesFromServer(message);
				}
				else if (params[0] == "OK")
				{
					this->isAuthenticated = true;
				}
				else if ("PRIVMSG")
				{
					processPRIVMSGFromSERVER(message);
				}
			}
			else
				sendToServer("UnAuthenticated");
		}
	}
	void processPRIVMSGFromSERVER(string message);
	void proccesNickNamesFromServer(string message);
	void startNewServerConnection(string pass, string ipAddrees);
	void openConnection(string pass, string ipAddrees)
	{
		if (serversIp.find(ipAddrees) == serversIp.end())
		{
			cout << "No server with ip" + ipAddrees;
			return;
		}
		int server_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (server_socket == -1)
			throw runtime_error("faild to create socket");
		sockaddr_in server_address{};
		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(stoi(serversIp[ipAddrees]));
		server_address.sin_addr.s_addr = inet_addr(ipAddrees.c_str());
		if (connect(server_socket, (sockaddr *)&server_address, sizeof(server_address)) == -1)
			cerr << "could not connect to server" << strerror(errno) << endl;
		this->server_socket = server_socket;
	}
};

class ChatServer
{
public:
	ChatServer() : running(true) {}
	void start();
	bool isClient(int socket)
	{
		if (retrieveSourcePort(socket) >= 9000)
			return true;
		return false;
	}
	int retrieveSourcePort(int socket_fd)
	{
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);

		// Retrieve the address information of the connected socket
		if (getsockname(socket_fd, (struct sockaddr *)&addr, &len) == -1)
		{
			perror("getsockname");
			return -1;
		}

		// Extract the source port from the address structure
		unsigned short source_port = ntohs(addr.sin_port);

		return source_port;
	}
	void stop()
	{
		running = false;
		for (auto &thread : threads)
		{
			thread.join();
		}
		close(server_socket);
	}
	void executeConnectCommand(string pass, string serverIp);
	string readMessageFromSockt(int socket);

private:
	string getClientIP(int socket)
	{
		sockaddr_in address;
		socklen_t address_len = sizeof(address);
		getpeername(socket, (sockaddr *)&address, &address_len);
		return inet_ntoa(address.sin_addr);
	}
	int server_socket;
	std::mutex mutex;
	atomic<bool> running;
};

class ClientManager
{
public:
	ClientManager();
	~ClientManager();
	static bool isNickNameAvialble(string nickName);
	static bool isValidNickName(string nickName);
	static string sendPrivateMessageToClient(string message, string toNickName, string fromClient);
};
class Client
{
public:
	Client() = default;
	Client(const Client &org)
	{
		this->nickName = org.nickName;
		this->client_socket = org.client_socket;
		this->maxChannel = org.maxChannel;
		this->numOfCurrentChannel = org.numOfCurrentChannel;
		this->pass = org.pass;
	};
	Client(int client_socket);
	void handleClient(int client_socket);
	void joinCommand(vector<string> params);
	void TimeCommand(vector<string>);
	string getCurrentTime();
	void NickCommand(vector<string> params);
	void fitchNickCommand(string params);
	void sendToClient(string message);
	void sendToClient(int numericRepliesNumber);
	void sendToClient(int numericRepliesNumber, string param);
	void sendToClient(int numericRepliesNumber, vector<string> param);
	void UserCommand(vector<string> params, string message);
	string getWelcomeMessageParam();
	string getHostName();
	string getClientIP(int socket);
	void listCommand(vector<string> params);
	void partCommand(string params);
	void PRIVMSGCommand(string message);
	const static ClientManager clientManager;
	void topicCommand(vector<string> params, string massage);
	void quitCommand(vector<string> param);
	void PassCommand(vector<string> param);
	void LogInCommand(string message);
	void loadClinetInfo(string nickName);
	void SaveClientInfo();
	string getClientNickName()
	{
		return this->nickName;
	}
	bool canClientRegesterInMoreChannels()
	{
		return maxChannel > numOfCurrentChannel;
	}
	bool registered;
	bool logged_in;
	string nickName;
	string userName; // fullname
	string ipAddr;
	string realName;
	char mode;
	int client_socket;
	bool isClient_socket_Live = true;
	vector<thread> threads;
	int maxChannel = 3;
	int numOfCurrentChannel = 0;
	bool onOthereServer = false;
	string serverIp;
	string pass;
};

class Channel
{
public:
	int invit_only;
	string topic;
	int key;
	int limit;
	bool topic_restriction;
	string name;
	string time_creation;
	unordered_map<string, Client> channelMembers;
	Channel() {}
	Channel(string name)
	{
		this->name = name;
	}
	string clearTopic(string userNickName)
	{
		if (!isUserChannelMember(userNickName))
			return numericReplies[441];
		topic = "";
		sendTextToAllUsers(userNickName + " clear channel topic.");
		return "";
	}
	bool isUserChannelMember(string userNickName)
	{
		return channelMembers.find(userNickName) != channelMembers.end();
	}
	string addUser(Client client)
	{
		if (!client.canClientRegesterInMoreChannels())
			return numericReplies[405];
		if (isUserChannelMember(client.nickName))
		{
			return "443 : " + client.nickName + numericReplies[443];
		}
		channelMembers.insert(make_pair(client.nickName, client));
		sendTextToAllUsersException(client.nickName + " has joind the chennel.", client.nickName);
		client.numOfCurrentChannel++;
		return channelInfo();
	}
	string channelInfo()
	{
		string res = "Join confirmed\n";
		res += this->getTopic() + "\n";
		res += channelMembersName();
		return res;
	}
	string channelInfoToExchange()
	{
		string res = "-" + this->name + " ";
		res += getChennelMembersNameWithPermistion();
		return res;
	}
	string setChannelTopic(string topic, string userNickName)
	{
		if (!isUserChannelMember(userNickName))
			return numericReplies[442];
		this->topic = topic;
		sendTextToAllUsers(userNickName + " set channel topic to " + topic);
		return "";
	}
	string getTopicForUser(string userNickName)
	{
		if (!isUserChannelMember(userNickName))
			return numericReplies[442];
		return getTopic();
	}
	void sendTextToAllUsers(string text)
	{
		for (const auto &pair : channelMembers)
		{
			Client c = pair.second;
			c.sendToClient(text);
		}
	}
	string sendTextToAllUsersException(string text, string exceptionNickName = "")
	{
		string message = text;
		if (!exceptionNickName.empty())
		{
			message += " from " + exceptionNickName;
		}
		for (const auto &pair : channelMembers)
		{
			if (pair.second.nickName != exceptionNickName)
			{
				Client c = pair.second;
				c.sendToClient(message);
			}
		}
		return "";
	}
	string getTopic()
	{
		if (topic == "")
		{
			return "331 " + name + " : no topic is set";
		}
		else
			return "332 " + name + ": " + topic;
	}
	void setTopic(string topic)
	{
		this->topic = topic;
	}
	string channelMembersName()
	{
		string res = numericReplies[353] + '\n';
		res += getChennelMembersNameWithPermistion();
		res += numericReplies[336] + " " + name + " :End of NAMES list.";
		return res;
	}
	string getChennelMembersNameWithPermistion()
	{
		string res;
		for (const auto &pair : channelMembers)
			res.append('@' + pair.first + '\n');
		return res;
	}

	string part(string userNickName, string partMessage = "left the channel.")
	{
		if (!isUserChannelMember(userNickName))
		{
			return numericReplies[442];
		}
		channelMembers.at(userNickName).numOfCurrentChannel--;
		for (auto it = channelMembers.begin(); it != channelMembers.end();)
		{
			if (it->first == userNickName)
			{
				it = channelMembers.erase(it);
			}
			else
			{
				++it;
			}
		}

		for (const auto &pair : channelMembers)
		{
			Client c = pair.second;
			c.sendToClient(userNickName + " " + partMessage);
		}
		return "You just left the " + name + " Channel\n";
	}
	string channelPrifInfo()
	{
		return name + ":" + topic;
	}
};

class ChannelManager
{
private:
	unordered_map<string, Channel> channels;

public:
	string getChannelsInfoToExchange()
	{
		string res = "";
		for (const auto &pair : channels)
		{
			Channel channel = pair.second;
			res += channel.channelInfoToExchange();
		}
		return res;
	}
	string joinClientToChannels(vector<string> channels, string nickName)
	{
		string res = "";
		for (string channel : channels)
			res += joinClientToChannel(channel, nickName);
		return res;
	}
	string joinClientToChannel(string channelName, string nickName)
	{
		if (!isAvalidChannelName(channelName))
			return channelName + "	" + numericReplies[403];
		if (!isChannelExist(channelName))
		{
			channels.insert(make_pair(channelName, Channel(channelName)));
		}

		Client *c = getClientWithNickName(nickName);
		Client df = *c;
		return channels[channelName].addUser(df);
	}
	Client *getClientWithNickName(const string &name)
	{
		clients_mutex.lock();
		for (Client *c : clients)
		{
			if (c->nickName == name)
			{
				clients_mutex.unlock();
				return c; // Return a ref of object
			}
		}
		clients_mutex.unlock();
		throw runtime_error("Client not found with nickname: " + name);
	}
	Client getClientWithNickName2(const string &name)
	{
		for (Client *c : clients)
		{
			if (c->nickName == name)
			{
				return *c; // deref
			}
		}
		throw runtime_error("Client with nickname '" + name + "' not found");
	}
	bool isAvalidChannelName(string name)
	{
		if (name.size() <= 1 || name.size() > 50)
			return false;
		return (name[0] == '&' || name[0] == '!' || name[0] == '#' || name[0] == '+');
	}
	void removeClientFromAllChannels(string nickName)
	{
		for (auto pair : channels)
		{
			Channel s = pair.second;
			s.part(nickName);
			channels[s.name] = s;
		}
	}
	string list(string channelName)
	{
		if (isChannelExist(channelName))
			return channels[channelName].channelMembersName();
		return "403	" + channelName + " :No such channel";
	}
	string getPrifInfor(string channelName)
	{
		if (isChannelExist(channelName))
			return channels[channelName].channelPrifInfo();
		return "403	" + channelName + " :No such channel";
	}
	string list(vector<string> chennelsNames)
	{
		string res = "322\n";
		for (int i = 0; i < chennelsNames.size(); i++)
			res += getPrifInfor(chennelsNames[i]);
		res += numericReplies[323];
		return res;
	}
	string listAll()
	{
		string res = "322\n";
		for (const auto &pair : channels)
		{
			Channel c = pair.second;
			res += c.channelPrifInfo();
		}
		res += numericReplies[323];
		return res;
	}
	string sendMessageToChennal(string message, string targetChennal, string fromNickName)
	{
		if (channels.find(targetChennal) == channels.end())
			return numericReplies[403] + " " + targetChennal;
		return channels[targetChennal].sendTextToAllUsersException(message, fromNickName);
	}
	string partFrom(string userNickName, vector<string> channelsName, string partMessage = "left the channel.")
	{
		string res = "";
		for (size_t i = 0; i < channelsName.size(); i++)
		{

			if (!isChannelExist(channelsName[i]))
				res.append(channelsName[i] + " " + numericReplies[403]);
			else
				res += channels.at(channelsName[i]).part(userNickName, partMessage);
		}
		return res;
	}
	string clearTopicForChennalName(string channelName, string userNickName)
	{
		if (!isAvalidChannelName(channelName) || channels.find(channelName) == channels.end())
		{
			return numericReplies[403];
		}
		return channels.at(channelName).clearTopic(userNickName);
	}
	string getChannelTopic(string channelName, string userNickName)
	{
		if (!isChannelExist(channelName))
			return numericReplies[403];
		return channels.at(channelName).getTopicForUser(userNickName);
	}
	bool isChannelExist(string channelName)
	{
		return channels.find(channelName) != channels.end();
	}
	string setTopic(string channelName, string topic, string userNickName)
	{
		if (!isChannelExist(channelName))
			return numericReplies[403];
		return channels.at(channelName).setChannelTopic(topic, userNickName);
	}
};
ChannelManager channelManager = ChannelManager();

Client::Client(int client_socket)
{
	this->client_socket = client_socket;
	threads.emplace_back(thread(&Client::handleClient, this, client_socket));
	getHostName();
}

void Client::handleClient(int client_socket)
{
	const auto client_ip = getClientIP(client_socket);
	// cout << "client connected: " << client_ip << endl;
	try
	{

		while (isClient_socket_Live)
		{
			char message[1024];

			int bytes_read = recv(client_socket, message, sizeof(message), 0);
			if (bytes_read <= 0)
			{
				break;
			}
			cout << string(*message, bytes_read) << endl;
			vector<string> params = split(message, ' ');
			if (inClientCommadSet(params[0]))
			{
				if (params[0] == "PASS")
				{
					PassCommand(params);
				}
				else if (params[0] == "NICK")
				{
					fitchNickCommand(message);
				}
				else if (params[0] == "QUIT")
					quitCommand(params);
				else if (registered)
				{
					if (params[0] == "USER")
					{
						UserCommand(params, message);
					}
					else if (params[0] == "TIME")
					{
						this->TimeCommand(params);
					}
					else if (params[0] == "JOIN")
					{
						joinCommand(params);
					}
					else if (params[0] == "PART")
					{
						partCommand(message);
					}
					else if (params[0] == "LIST")
					{
						this->listCommand(params);
					}
					else if (params[0] == "NAMES")
					{
						// namesCommand(params);
					}
					else if (params[0] == "TOPIC")
					{
						topicCommand(params, message);
					}
					else if (params[0] == "PRIVMSG")
					{
						PRIVMSGCommand(message);
					}
				}
				else
				{
					if (params[0] == "USER")
						UserCommand(params, message);
					else
						sendToClient(451);
				}
			}
			else
			{
				sendToClient(421, params);
			}

			memset(message, 0, sizeof(message));
		}
	}
	catch (exception e)
	{
		cout << e.what() << endl;
	}
	close(client_socket);

	// cout << "client disconnected: " << client_ip << endl;
}
void Client::PassCommand(vector<string> params)
{
	if (this->pass != "")
		sendToClient("you set the pass before");
	else if (params.size() == 1)
	{
		sendToClient(461);
	}
	else
	{
		this->pass = params[1];
	}
}
void Client::quitCommand(vector<string> params)
{
	isClient_socket_Live = false;
	close(client_socket);
	string message = "client  gracefully quit";
	if (params.size() > 1)
		message += " with " + params[1] + " message";
	cout << message << endl;
}
void Client::topicCommand(vector<string> params, string massage)
{
	if (params.size() == 1)
	{
		sendToClient(461, params);
	}
	else if (params.size() == 2)
	{
		sendToClient(channelManager.getChannelTopic(params[1], nickName));
	}
	else if (params.size() == 3 && params[2].size() == 1 && params[2][0] == ':')
	{
		sendToClient(channelManager.clearTopicForChennalName(params[1], this->nickName));
	}
	else
	{
		int startIndexOfMessage = massage.find(':');
		if (startIndexOfMessage < 0)
		{
			sendToClient(412);
			return;
		}
		string topic = split(massage, ':')[1];
		sendToClient(channelManager.setTopic(params[1], topic, nickName));
	}
}
void Client::PRIVMSGCommand(string message)
{
	vector<string> params = split(message, ' ');
	if (params.size() == 1)
	{
		vector<string> vs;
		vs.push_back("PRIVMSG");
		sendToClient(461, vs);
	}
	else
	{
		int startIndexOfMessage = message.find(':');
		if (startIndexOfMessage < 0)
		{
			sendToClient(412);
			return;
		}
		else
		{
			string TextToSend = message.substr(startIndexOfMessage);
			string msgtarget = params[1];
			if (channelManager.isAvalidChannelName(params[1]))
			{
				sendToClient(channelManager.sendMessageToChennal(TextToSend, msgtarget, nickName));
			}
			else
			{
				sendToClient(clientManager.sendPrivateMessageToClient(TextToSend, msgtarget, nickName));
			}
		}
	}
}

void Client::partCommand(string message)
{
	vector<string> params = split(message, ' ');
	if (params.size() == 1)
		sendToClient(461, {message});
	else if (params.size() == 1)
	{
		sendToClient(461, {message});
		return;
	}
	else
	{

		vector<string> p = split(message, ':');
		vector<string> targetChannels = split(params[1], ',');
		if (p.size() > 1)
			sendToClient(channelManager.partFrom(nickName, targetChannels, p[1]));
		else
			sendToClient(channelManager.partFrom(nickName, targetChannels));
	}
}
void Client::joinCommand(vector<string> params)
{
	if (params.size() == 1)
	{
		sendToClient(461, params);
	}
	else if (params.size() == 2 && params[1][0] == '0')
	{
		channelManager.removeClientFromAllChannels(nickName);
		sendToClient("You just left all Channels!\n");
	}
	else
	{
		sendToClient(channelManager.joinClientToChannels(split(params[1], ','), nickName));
	}
}
void Client::TimeCommand(vector<string> params)
{
	if (params.size() == 1 || (params[1] == s_nickname && params.size() == 2))
	{
		sendToClient(s_nickname + " :" + getCurrentTime());
	}
	else if (params.size() > 2)
	{
		sendToClient(407);
	}
	else
	{
		sendToClient("402 : " + params[1] + " :No such server");
	}
}
string Client::getCurrentTime()
{
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	return (" %s", asctime(timeinfo));
}
void Client::fitchNickCommand(string message)
{
	if (message.find(':') != std::string::npos)
		LogInCommand(message);
	else
		NickCommand(split(message, ' '));
}
void Client::LogInCommand(string message)
{
	// NICK Wiz :wizpassword
	vector<string> parms = split(message, ' ');
	string NickName = parms[1];
	string pass = split(parms[2], ':')[1];
	if (decodePass.find(NickName) != decodePass.end() && decodePass[parms[1]] == pass)
		loadClinetInfo(parms[1]);
	else
		sendToClient(464);
}
void Client::loadClinetInfo(string nickName)
{
	int index = 0;
	for (Client *c : clients)
	{
		index++;
		if (c->nickName == nickName)
		{
			c->client_socket = this->client_socket;
			c->isClient_socket_Live = true;
			this->registered = true;
			c->isClient_socket_Live = true;
			sendToClient("welcome back!");
			c->handleClient(this->client_socket);
			break;
		}
	}
	clients[index] = this;
}
void Client::SaveClientInfo()
{
	string data = this->nickName + " " + base64_encode(this->pass) + "\n";
	std::ofstream outFile; // Create an output file stream object
	// Open the file in append mode
	outFile.open(clientDataFileName, std::ios::app);
	// Check if the file opened successfully
	if (!outFile)
	{
		std::cerr << "Unable to open file";
		return;
	}
	// Write data to the file (appending)
	outFile << data;
	// Close the file
	outFile.close();
	std::cout << "Data has been appended to the file.\n";
}

void Client::NickCommand(vector<string> params)
{
	if (params.size() == 1)
	{
		sendToClient(431);
	}
	else if (params.size() > 2)
	{
		sendToClient(432, params);
	}
	else
	{
		clients_mutex.lock();
		if (!ClientManager::isNickNameAvialble(params[1]))
			sendToClient(433);
		else if (!ClientManager::isValidNickName(params[1]))
			sendToClient(432, params);
		else
		{
			this->nickName = params[1];
		}
		clients_mutex.unlock();
	}
}
void Client::sendToClient(string message)
{
	if (message.empty())
		return;
	int sent_bytes = send(client_socket, message.c_str(), message.size(), 0);
	if (sent_bytes == -1)
		cerr << "eror sending data from sendtoclient(string)" << strerror(errno) << endl;
	else
		cout << "sent \"" << sent_bytes << message << "\" bytes to " << getClientIP(client_socket) << endl;
}

void Client::sendToClient(int numericRepliesNumber)
{
	string messageToClient = numericReplies[numericRepliesNumber];
	sendToClient(messageToClient);
}
void Client::sendToClient(int numericRepliesNumber, string param)
{
	string messageToClient = numericReplies[numericRepliesNumber] + "\n" + param;
	sendToClient(messageToClient);
}
void Client::sendToClient(int numericRepliesNumber, vector<string> param)
{
	string messageToClient;
	string str = "";
	switch (numericRepliesNumber)
	{
	case 1:
		messageToClient = "001 :welcome to Calculus IRC " + param[0] + "!" + param[1] + "@" + Host_Name;
		messageToClient += "\n002 Your host is " + s_nickname + ", running version 1.0\n";
		messageToClient += "003 This server was created " + serverTime + "\n" + "004 " + s_nickname + " 1.0 * *";
		break;
	case 366:
		//<channel> :End of NAMES list
		messageToClient = param[0] + "  :End of NAMES list";
	case 331:
		//"<channel> :No topic is set"
		messageToClient = param[0] + " :No topic is set";
		break;

	case 401:
		//<nickname> :No such nick/channel
		messageToClient = param[0] + " :No such nick/channel";
		break;
	case 402:
		//<server name> :No such server
		messageToClient = param[0] + " :No such server";
	case 403:
		//<channel name> :No such channel
		messageToClient = param[0] + " :No such channel";
		break;
	case 405:
		//<channel name> :You have joined too many channels
		messageToClient = param[0] + " :You have joined too many channels";
		break;
	case 406:
		//<nickname> :There was no such nickname
		messageToClient = param[0] + " " + param[1] + " :is already on channel\n";
		break;
	case 411:
		//: No recipient given (<command>)
		messageToClient = ":No recipient given (" + param[0] + ")";
		break;
	case 421:
		//<command> :Unknown command
		messageToClient = param[0] + " :Unknown command";
		break;
	case 432:
		//<nick> :Erroneous nickname;
		messageToClient = param[0] + " :Erroneous nickname";
		break;
	case 433:
		//<nick> :Nickname is already in use
		messageToClient = param[0] + " :Nickname is already in use";
		break;
	case 443:
		//<user> <channel> :is already on channel
		messageToClient = param[0] + " " + param[1] + " :is already on channel";
		break;
	case 461:
		//<command> :Not enough parameters
		for (int i = 0; i < param.size(); i++)
		{
			str = str + param[i] + " ";
		}
		messageToClient = param[0] + " :Not enough parameters";
		break;

	default:

		break;
	}
	if (numericRepliesNumber != 1)
	{
		messageToClient = to_string(numericRepliesNumber) + "	" + messageToClient;
	}
	sendToClient(messageToClient);
}
void Client::UserCommand(vector<string> params, string message)
{
	if (registered)
	{
		sendToClient(462);
	}
	else if (params.size() < 5)
	{
		this->sendToClient(461, params);
	}
	else if (nickName.empty())
	{
		this->sendToClient(431);
	}
	else if (!userName.empty())
	{
		this->sendToClient(462);
	}
	else if (params[2].size() > 1)
	{
		sendToClient(472);
	}
	else if (params[4][0] != ':')
	{
		sendToClient(472);
	}
	else
	{
		this->userName = params[1];
		this->mode = params[2][0];
		this->realName = split(message, ':')[1]; // may contains spaces
		registered = true;
		string paramsMassge = getWelcomeMessageParam();
		vector<string> vs = {this->nickName, this->userName};
		this->sendToClient(1, vs);
		this->SaveClientInfo();
		decodePass.emplace(this->nickName, this->pass);
	}
}
string Client::getWelcomeMessageParam()
{
	return this->nickName + "!" + this->userName + "@" + getHostName();
}
string Client::getHostName()
{
	char hostname[HOST_NAME_MAX];
	gethostname(hostname, HOST_NAME_MAX);
	Host_Name = hostname;
	return hostname;
}
string Client::getClientIP(int socket)
{
	sockaddr_in address;
	socklen_t address_len = sizeof(address);
	getpeername(socket, (sockaddr *)&address, &address_len);
	return inet_ntoa(address.sin_addr);
}

void Client::listCommand(vector<string> params)
{

	if (params.size() == 1)
	{
		sendToClient(channelManager.listAll());
	}
	else if (params.size() > 2 && s_nickname != params[2])
	{
		sendToClient(params[1] + " :" + numericReplies[402]);
	}
	else
	{
		vector<string> channelsName = split(params[1], ',');
		sendToClient(channelManager.list(channelsName));
	}
}

ChatServer server;
void ChatServer::start()
{
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket == -1)
	{
		throw runtime_error("couldnot create socket");
	}
	const int myPort = port_num;
	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port_num);
	if (bind(server_socket, (sockaddr *)&address, sizeof(address)) == -1)
	{
		throw runtime_error("couldnot bind");
	}
	if (listen(server_socket, SOMAXCONN) == -1)
	{
		throw runtime_error("error cant listen");
	}

	while (running)
	{
		int scocket = accept(server_socket, nullptr, nullptr);

		if (scocket == -1)
		{
			throw runtime_error("could not accept connection request");
		}
		string message = readMessageFromSockt(scocket);
		if (message == "SERVER")
		{
			ServerConnection *s = new ServerConnection(scocket);
			// handelServerRequest(scocket);
		}
		else
		{
			Client *newClient = new Client(scocket);
			clients.emplace_back(newClient);
		}
	}
}
string ChatServer::readMessageFromSockt(int socket)
{
	char message[1024];
	int bytes_read = recv(socket, message, sizeof(message), 0);
	if (bytes_read <= 0)
	{
		cout << "Error";
	}
	message[bytes_read] = '\0';
	string res = string(message);
	memset(message, 0, sizeof(message));
	return res;
}
void startServer(ChatServer &chatServer)
{
	chatServer.start();
}
void startServerConnection(string pass, string ipAddrees)
{
	ServerConnection serverConnection = ServerConnection();
	serverConnection.startNewServerConnection(pass, ipAddrees);
}

ClientManager::ClientManager()
{
}

ClientManager::~ClientManager()
{
}

bool ClientManager::isNickNameAvialble(string nickName)
{
	for (Client *c : clients)
	{
		if (c->nickName == nickName)
			return false;
	}
	return true;
}

bool ClientManager::isValidNickName(string nickName)
{
	return nickName.length() <= 9 && nickName[0] != '&' && nickName[0] != '!' && nickName[0] != '+' && nickName[0] != '#';
}
string ClientManager::sendPrivateMessageToClient(string message, string toNickName, string fromNickName)
{
	for (Client *c : clients)
	{
		if (c->nickName == toNickName)
		{
			if (c->onOthereServer)
			{ // PRIVMSG A :MESSAGETEXT
				c->sendToClient("PRIVMSG " + toNickName + " :" + message);
			}
			else
				c->sendToClient(message);
			return "";
		}
	}
	return numericReplies[401];
}
const ClientManager Client::clientManager;
void readServerConfig(std::string &nickname, int &port)
{
	std::ifstream serverConfig("server.conf");
	std::string line;
	while (std::getline(serverConfig, line))
	{
		if (line.find("NICK=") != std::string::npos)
			nickname = line.substr(line.find("=") + 1);
		else if (line.find("PORT=") != std::string::npos)
			port = std::stoi(line.substr(line.find("=") + 1));
		else if (line.find("PASS=") != std::string::npos)
		{
			s_pass = line.substr(line.find("=") + 1);
		}

		else if (line.find("SOCK_ADDR=") != std::string::npos)
		{
			vector<string> temp = split(line.substr(line.find("=") + 1), ':');
			serversIp[temp[0]] = temp[1];
		}
	}
	serverConfig.close();
}
void ChatServer::executeConnectCommand(string pass, string serverIp) // this should be in a thrad
{
	if (serversIp.find(serverIp) == serversIp.end())
	{
		cout << "No server with ip" + serverIp;
		return;
	}
	int client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket == -1)
		throw runtime_error("faild to create socket");
	sockaddr_in server_address{};
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(stoi(serversIp[serverIp]));
	server_address.sin_addr.s_addr = inet_addr(serverIp.c_str());
	if (connect(client_socket, (sockaddr *)&server_address, sizeof(server_address)) == -1)
		cerr << "could not connect to server" << strerror(errno) << endl;
	while (true)
	{
		char message[1024];

		int bytes_read = recv(client_socket, message, sizeof(message), 0);
		if (bytes_read <= 0)
		{
			break;
		}
		cout << string(*message, bytes_read) << endl;
	}
	// thread receive_thread(receiveMessage, client_socket);
}
void setCommandSet();

bool ServerConnection::passCommand(vector<string> params)
{
	if (isAuthenticated)
	{
		sendToServer(numericReplies[462]);
		return false;
	}
	else if (params.size() < 2)
	{
		sendToServer("Need More params");
		return false;
	}
	else if (base64_decode(params[1]).compare(s_pass) == 0)
	{
		isAuthenticated = true;
		sendToServer("OK");
		sendToServer(getUsersNickNamesMessage());
		return true;
	}
	isAlive = false;
	return false;
}
void ServerConnection::sendToServer(string message)
{
	if (message.empty())
		return;
	int sent_bytes = send(server_socket, message.c_str(), message.size(), 0);
	if (sent_bytes == -1)
		cerr << "eror sending data from sendtoclient(string)" << strerror(errno) << endl;
	else
		cout << "sent \"" << sent_bytes << message << "\" bytes to " << server_socket << endl;
}
void ServerConnection::JoinCommand(string message)
{
}
string ServerConnection::getUsersNickNamesMessage()
{
	string NickNamesMessage = "NickNames: ";
	string res = "";
	for (Client *cli : clients)
	{
		NickNamesMessage += cli->getClientNickName();
	}
	return NickNamesMessage;
}
void ServerConnection::processPRIVMSGFromSERVER(string message)
{
	// PRIVMSG A :MESSAGETEXT
	vector<string> params = split(message, ' ');
	ClientManager::sendPrivateMessageToClient(params[2], params[1], "");
}
void ServerConnection::proccesNickNamesFromServer(string message)
{
	vector<string> params = split(message, ':');
	if (params.size() < 2)
		return;
	vector<string> nickNames = split(params[1], ' ');
	for (string s : nickNames)
	{
		Client *client = new Client();
		client->nickName = s;
		client->onOthereServer = true;
		client->client_socket = server_socket;
	}
}
string ServerConnection::getNJoinMessage()
{
	string infoMessage = "NJOIN ";
	infoMessage += channelManager.getChannelsInfoToExchange();
	return infoMessage;
}
void ServerConnection::startNewServerConnection(string pass, string ipAddrees)
{
	openConnection(pass, ipAddrees);
	sendToServer("SERVER");
	sendToServer("PASS " + base64_encode(pass));
	proccesRequest(readMessageFromSockt());
	if (this->isAuthenticated)
	{
		proccesRequest(readMessageFromSockt());
	}
	sendToServer(getUsersNickNamesMessage());
	proccesRequest(readMessageFromSockt());
	sendToServer("NJOIN");
	proccesRequest(readMessageFromSockt());
	handelServerRequest();
}

int main()
{
	int myPort;

	readServerConfig(s_nickname, myPort);
	const int myPortConst = myPort;

	port_num = myPort;
	setNumericReplies();
	CurrentServerTimeAsString();
	setCommandSet();
	setServerCommandSet();
	read_usr_pass(clientDataFileName);
	try
	{
		thread startServerThread(startServer, ref(server));
		string input;
		bool readInput = true;
		string pass = "";
		string ipConnect = "";
		while (readInput)
		{
			getline(cin, input);
			if (input == "quit")
			{
				readInput = false;
				server.stop();
			}
			else
			{
				vector<string> in = split(input, ' ');
				if (in[0] == "PASS")
				{
					pass = in[1];
				}
				else if (in[0] == "SERVER")
				{
					ipConnect = in[1];
					thread startServerConnectionThread(startServerConnection, pass, in[1]);
					startServerConnectionThread.join();
				}
			}
		}
	}
	catch (const exception &e)
	{
		cerr << "Error: " << e.what() << endl;
	}
	return 0;
}
void read_usr_pass(string fileName)
{
	filesystem::path filePath = fileName;
	// Check if the file exists
	if (std::filesystem::exists(filePath))
	{
		std::ifstream file(fileName);
		std::string line;
		while (getline(file, line))
		{
			// Use a string stream to extract data
			std::istringstream iss(line);
			std::string key, value;
			if (!(iss >> key >> value))
			{ // Extract two strings from the line
				std::cerr << "Error reading line from file." << std::endl;
				break;
			}
			// Store the data in the hashmap
			decodePass[key] = value;
		}

		// Display the data stored in the hashmap
		for (const auto &pair : decodePass)
		{
			std::cout << pair.first << " : " << pair.second << std::endl;
		}
	}
	else
	{ // Create file if not exist
		std::ofstream file(filePath);
	}
}

void setNumericReplies()
{
	numericReplies[1] = "001_Welcome to the Internet Relay Network";
	numericReplies[401] = "401_ERR_NOSUCHNICK";
	numericReplies[402] = "402_ERR_NOSUCHSERVER";
	numericReplies[403] = "403    :no such channel";
	numericReplies[404] = "404    cant send to channel";
	numericReplies[405] = "405    ERR_TOOMANYCHANNELS";
	numericReplies[406] = "406    ERR_WASNOSUCHNICK";
	numericReplies[406] = "407    ERR_TOOMANYTARGETS";
	numericReplies[408] = "408    ERR_NOSUCHSERVICE";
	numericReplies[409] = "409    ERR_NOORIGIN";
	numericReplies[411] = "411    :No recipient given";
	numericReplies[412] = "412    :No text to send";
	numericReplies[413] = "413    ERR_NOTOPLEVEL";
	numericReplies[414] = "414    ERR_WILDTOPLEVEL";
	numericReplies[415] = "415    ERR_BADMASK";
	numericReplies[421] = "421    ERR_UNKNOWNCOMMAND";
	numericReplies[422] = "422    ERR_NOMOTD";
	numericReplies[423] = "423    ERR_NOADMININFO";
	numericReplies[424] = "424    ERR_FILEERROR";
	numericReplies[431] = "431    :No nickname given";
	numericReplies[432] = "432    :Erroneous nickname";
	numericReplies[433] = "433    :Nickname is already in use";
	numericReplies[437] = "437    ERR_UNAVAILRESOURCE";
	numericReplies[441] = "441    :user not in channel";
	numericReplies[442] = "442    :You're not on that channel";
	numericReplies[443] = ":is already on channel";
	numericReplies[444] = "444    ERR_NOLOGIN";
	numericReplies[445] = "445    ERR_SUMMONDISABLED";
	numericReplies[446] = "446    ERR_USERSDISABLED";
	numericReplies[451] = "451    :You have not registered";
	numericReplies[461] = "461    ERR_NEEDMOREPARAMS";
	numericReplies[462] = "462    :Unauthorized command (already registered)";
	numericReplies[463] = "463    ERR_NOPERMFORHOST";
	numericReplies[464] = "464    ERR_PASSWDMISMATCH";
	numericReplies[465] = "465    ERR_YOUREBANNEDCREEP";
	numericReplies[466] = "466    ERR_YOUWILLBEBANNED";
	numericReplies[467] = "467    ERR_KEYSET";
	numericReplies[471] = "471    ERR_CHANNELISFULL";
	numericReplies[472] = "472    ERR_UNKNOWNMODE";
	numericReplies[473] = "473    ERR_INVITEONLYCHAN";
	numericReplies[474] = "474    ERR_BANNEDFROMCHAN";
	numericReplies[475] = "475    ERR_BADCHANNELKEY";
	numericReplies[476] = "476    ERR_BADCHANMASK";
	numericReplies[477] = "477    ERR_NOCHANMODES";
	numericReplies[478] = "478    ERR_BANLISTFULL";
	numericReplies[481] = "481    ERR_NOPRIVILEGES";
	numericReplies[482] = "482    ERR_CHANOPRIVSNEEDED";
	numericReplies[483] = "483    ERR_CANTKILLSERVER";
	numericReplies[484] = "484    ERR_RESTRICTED";
	numericReplies[485] = "485    ERR_UNIQOPPRIVSNEEDED";
	numericReplies[491] = "491    ERR_NOOPERHOST";
	numericReplies[501] = "501    ERR_UMODEUNKNOWNFLAG";
	numericReplies[402] = "402    ERR_USERSDONTMATCH";
	numericReplies[366] = "366    :end of names";
	numericReplies[442] = "442    :You're not on that channel";
	numericReplies[331] = "331    RPL_NOTOPIC {} : No topic is set ";
	numericReplies[464] = "464    ERR_PASSWDMISMATCH :Password incorrect";

	numericReplies[353] = "End of names";
	numericReplies[323] = "\n323 :End of LIST";
}
vector<string> split(const string &s, char delim)
{
	vector<string> result;
	stringstream ss(s);
	string item;
	while (getline(ss, item, delim))
	{
		result.push_back(item);
	}
	return result;
}
void CurrentServerTimeAsString()
{
	time_t currentTime = time(nullptr);
	const int bufferSize = 80;
	char buffer[bufferSize];
	strftime(buffer, bufferSize, "%Y-%m-%d %H:%M:%S", localtime(&currentTime));
	serverTime = string(buffer);
}
void setServerCommandSet()
{
	serverCommandSet.insert("NICK");
	serverCommandSet.insert("NJOIN");
	serverCommandSet.insert("JOIN");
	serverCommandSet.insert("NickNames");
}
void setCommandSet()
{
	ClientCommandSet.insert("TOPIC");
	ClientCommandSet.insert("USER");
	ClientCommandSet.insert("NICK");
	ClientCommandSet.insert("LIST");
	ClientCommandSet.insert("TIME");
	ClientCommandSet.insert("NAMES");
	ClientCommandSet.insert("JOIN");
	ClientCommandSet.insert("QUIT");
	ClientCommandSet.insert("PART");
	ClientCommandSet.insert("PRIVMSG");
	ClientCommandSet.insert("PASS");
}
bool inClientCommadSet(string command)
{
	return ClientCommandSet.find(command) != ClientCommandSet.end();
}
bool inServerCommadSet(string command)
{
	return serverCommandSet.find(command) != ClientCommandSet.end();
}

string base64_encode(const std::string &in)
{
	std::string out;
	int val = 0, valb = -6;
	for (unsigned char c : in)
	{
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0)
		{
			out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6)
	{
		out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
	}
	while (out.size() % 4)
	{
		out.push_back('=');
	}
	return out;
}

string base64_decode(const std::string &in)
{
	std::string out;
	std::vector<int> T(256, -1);
	for (int i = 0; i < 64; i++)
	{
		T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
	}
	int val = 0, valb = -8;
	for (unsigned char c : in)
	{
		if (T[c] == -1)
			break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0)
		{
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}
