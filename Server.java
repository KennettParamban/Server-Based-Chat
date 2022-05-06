import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/*
 * Server class for the server based chat project
 */

public class Server {

	private DatagramSocket socket_server;
	byte[] string_data_reciver = new byte[1024];
	byte[] send_string_data = new byte[1024];
	History chat_history = null;

	//simulates a server on the terminal
	public Server(int port) 
	{
		//creates a set of keys and client names that should be given access to server.
		ConnectedClients client_connected = new ConnectedClients();
		client_connected.addSecretKey("A", "1234");
		client_connected.addSecretKey("B", "1234");
		client_connected.addSecretKey("C", "1234");
		client_connected.addSecretKey("D", "1234");
		chat_history = new History();

		try 
		{
			socket_server = new DatagramSocket(port);
		} 
		catch (Exception e) 
		{
			System.out.println("There is a error witht the DatagramSocket");
			System.out.println("Please reconnect with the string_dataDiagram");
			System.out.println(e);
			return;
		}

		int nextPort = port + 1;
		Random random = new Random(System.nanoTime());

		while (true) //infintely run the server so it doesnt close
		{
			try 
			{
				// Receive the next packet  from a client
				DatagramPacket packet_reciver = new DatagramPacket(string_data_reciver, string_data_reciver.length);
				socket_server.receive(packet_reciver);
				String string_data = new String(packet_reciver.getData()).trim(); //turn the packet data insto a string object

				String output = string_data; // base case output if the client data doesnt match expected output, jsut print the client data
				byte[] outputBytes = null;
				System.out.println("RECEIVED: " + string_data); //print the client data into the server side

				// Parse the input
				String[] string_dataArray = string_data.split("[(), ]+");
				for (int a = 0; a < string_dataArray.length; a++) 
				{
					string_dataArray[a] = string_dataArray[a].trim().toUpperCase(); //format string_data to uppercase to avoid case issues
				}

				// Switch on the command
				switch (string_dataArray[0]) { // check first word from client to server
				case ("HELLO"): //if that word is HELLO 
					// string_dataArray[1] contains the clientID
					String secretKey = client_connected.getSecretKey(string_dataArray[1]); //then the 2nd word should be client name
					if (secretKey != null) //if that client who said HELLO is one of the connected clients
					{
						String ran = Integer.toString(random.nextInt(1000)); //pick a random integer between 0 and 1000
						client_connected.addXRES(string_dataArray[1], A3(ran, secretKey));
						client_connected.addCKA(string_dataArray[1], A8(ran, secretKey));
						client_connected.addAvailable(string_dataArray[1], false);
						System.out.println(ran + secretKey); //print the random number and secret key to the server side
						output = "CHALLENGE(" + ran + ")"; //set output to a CHALLENGE before sending it to client
						outputBytes = output.getBytes(); // store output as bytes
					}
					else {
						System.out.println("ERROR: client not in the list of clients"); // client is not A, B, C, or D
						output = "ERROR: Not on client list"; //tell client this message
						outputBytes = output.getBytes(); //store output as bytes
					}

					break;
				case ("RESPONSE"): //if the client sends command RESPONSE
					// string_dataArray[1] contains the clientID
					// string_dataArray[2] contains the RES

					if (client_connected.getXRES(string_dataArray[1]).equals(string_dataArray[2])) { // if the client responds with the correct answer then send a success message
						client_connected.addPort(string_dataArray[1], nextPort);
						TCPServerThread tcp = new TCPServerThread(nextPort, string_dataArray[1], client_connected,
								chat_history);
						Thread thread = new Thread(tcp);
						thread.start();

						output = "AUTH_SUCCESS(" + random.nextInt(1000) + ", " + nextPort++ + ")"; //respond to the client with an AUTH_SUCCESS message
						outputBytes = encrypt(output, client_connected.getCKA(string_dataArray[1]));
					} 
					else {
						System.out.println("ERROR: Client response did not match xRES");
						output = "AUTH_FAIL";
						outputBytes = output.getBytes();
					}
					break;
				}

				// Send a packet back
				InetAddress returnIPAddress = packet_reciver.getAddress();
				int returnPort = packet_reciver.getPort();
				System.out.println(output);
				send_string_data = outputBytes;
				DatagramPacket sendPacket = new DatagramPacket(send_string_data, send_string_data.length,
						returnIPAddress, returnPort);
				socket_server.send(sendPacket);
			} 
			catch (Exception e) {
				System.out.println(e);
			}
		}
	}

	// Performs A3 encryption
	private String A3(String random, String secretKey) 
	{
		String plainText = random + secretKey;
		MessageDigest messgae_digest = null;
		try 
		{
			messgae_digest = MessageDigest.getInstance("SHA-1");
		} 
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		messgae_digest.reset();
		messgae_digest.update(plainText.getBytes());
		byte[] encrypted_cypher_string_key = messgae_digest.digest();
		BigInteger bigInt = new BigInteger(1, encrypted_cypher_string_key);
		String string_data = bigInt.toString(16);
		// Padding
		while (string_data.length() < 32) 
		{
			string_data = "0" + string_data;
		}
		// Added in due to input string_data from client being automatically made
		// uppercase
		string_data = string_data.toUpperCase();
		return string_data;
	}

	// Generate the encripted_ciphering key
	// Generated Key needs to be 16 byte length
	private byte[] A8(String ran, String string_key) // A8 function generates the encrypted key to be used later
	{
		String CK_A = ran + string_key;
		MessageDigest messgae_digest = null;
		try 
		{
			messgae_digest = MessageDigest.getInstance("MD5");
		} 
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		messgae_digest.reset();
		messgae_digest.update(CK_A.getBytes());
		byte[] encrypted_cypher_string_key = messgae_digest.digest();
		return encrypted_cypher_string_key;
	}

	// Works now
	private byte[] encrypt(String strClearText, byte[] encrypted_cypher_string_key) throws Exception 
	{
		String string_data = "";
		byte[] encrypted_string = null;

		try
		{
			SecretKeySpec server_key_spec = new SecretKeySpec(encrypted_cypher_string_key, "AES");
			Cipher encripted_cipher = Cipher.getInstance("AES");
			encripted_cipher.init(Cipher.ENCRYPT_MODE, server_key_spec);
			encrypted_string = encripted_cipher.doFinal(strClearText.getBytes());
			string_data = new String(encrypted_string, "ISO-8859-1");

		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			throw new Exception(e);
		}
		return encrypted_string;
	}

	public static void main(String args[]) {
		Server server = new Server(9879);
		if (args.length != 1)
			System.out.println("Use correct input of a port number");
		else
			server = new Server(Integer.parseInt(args[0]));
	}

	public class TCPServerThread implements Runnable 
	{
		ServerSocket welcome_socket;
		private final int port;
		private ConnectedClients client_connected;
		private final String client;
		private History chat_history;

		public TCPServerThread(int port, String client, ConnectedClients client_connected, History chat_history) 
		{
			this.port = port;
			this.client_connected = client_connected;
			this.client = client;
			this.chat_history = chat_history;
			try 
			{
				welcome_socket = new ServerSocket(port);
				System.out.println("Created TCP on: " + port);
			} 
			catch (IOException e) 
			{
				System.out.println(e);
			}
		}

		public void run() 
		{
			System.out.println("Listening on: " + port);
			String client_in_from_string;
			String client_out_to_str;
			String history_string;

			Socket connectionSocket = null;

			try {
				connectionSocket = welcome_socket.accept();
				System.out.println("Client " + client + " aclient_connectedepted: " + connectionSocket);
				DataInputStream inFromClient = new DataInputStream(
						new BufferedInputStream(connectionSocket.getInputStream()));
				DataOutputStream client_out_to = new DataOutputStream(connectionSocket.getOutputStream());
				client_connected.addStream(client, client_out_to);
				client_connected.setAvailable(client, true);

				int session = -1;
				int secoend_clientport = -1;
				String secoend_client_out_to_string = "";
				DataOutputStream client_out_toB = null;
				String secoend_client = "";
				byte[] secoend_clientCKA = null;

				client_in_from_string = inFromClient.readUTF();
				System.out.println("Received: " + client_in_from_string);
				client_in_from_string = decrypt(client_in_from_string, client_connected.getCKA(client));
				System.out.println("Decrypted Received: " + client_in_from_string);

				client_out_to_str = "CONNECTED";
				client_out_to_str = encrypt(client_out_to_str, client_connected.getCKA(client));
				client_out_to.writeUTF(client_out_to_str);

				String state = "IDLE";

				while (true) 
				{
					client_in_from_string = inFromClient.readUTF();
					System.out.println("Received: " + client_in_from_string);
					client_in_from_string = decrypt(client_in_from_string, client_connected.getCKA(client));
					System.out.println("Decrypted Received: " + client_in_from_string);

					switch (state) {
					case ("IDLE"):
						if (client_in_from_string.toUpperCase().equals("LOG OFF")) 
						{
							inFromClient.close();
							client_out_to.close();
							state = "DONE";
							break;
						}
						if (client_in_from_string.split("[()]")[0].equals("CHAT_STARTED")) 
						{
							secoend_client = client_in_from_string.split("[(), ]+")[2];
							secoend_clientCKA = client_connected.getCKA(secoend_client);

							session = Integer.parseInt(client_in_from_string.split("[(), ]+")[1]);
							secoend_clientport = client_connected.getPort(secoend_client);
							secoend_client_out_to_string = "";
							client_out_toB = client_connected.getStream(secoend_client);
							client_connected.setAvailable(client, false);

							state = "CHAT";
						}
						if (client_in_from_string.contains("HISTORY")) 
						{
							/*
							 * History view = new History(client); BufferedReader r = new BufferedReader(
							 * new FileReader( client ) ); String s = "", line = null; while ((line =
							 * r.readLine()) != null) { s += line; } System.out.print(s);
							 */
							System.out.println("Getting chat_history for " + client + " and "
									+ client_in_from_string.split("[()]")[1]);
							ArrayList<String> chat_historyArr = chat_history.getHistory(client,
									client_in_from_string.split("[()]")[1]);
							for (String s : chat_historyArr)
							{
								System.out.println(s);

								client_out_to_str = "HISTORY_RESP(" + s + ")";
								client_out_to_str = encrypt(client_out_to_str, client_connected.getCKA(client));
								client_out_to.writeUTF(client_out_to_str);
								client_out_to.flush();
							}
							// history_string = view.printToconsole();
							// history_string = encrypt(chat_historyString,
							// client_connected.getCKA(client));
							// client_out_to.writeUTF(history_string);
							// r.close();
							break;
							// client_out_toB.flush();

						}
						if (client_in_from_string.split("[()]")[0].equals("CHAT_REQUEST")) 
						{
							secoend_client = client_in_from_string.split("[()]")[1];
							secoend_clientCKA = client_connected.getCKA(secoend_client);

							if (secoend_clientCKA == null || !client_connected.getAvailable(secoend_client))
							{
								System.out.println(
										"User " + secoend_client + " is not currently online, please try again later");
								client_out_to_str = "UNREACHABLE(" + secoend_client + ")";
								client_out_to_str = encrypt(client_out_to_str, client_connected.getCKA(client));
								client_out_to.writeUTF(client_out_to_str);
							} 
							else 
							{
								session = client_connected.getSession();
								secoend_clientport = client_connected.getPort(secoend_client);
								secoend_client_out_to_string = "";
								client_out_toB = client_connected.getStream(secoend_client);
								System.out.println(client_out_toB.toString());

								System.out.println("Create chat with " + secoend_client + " with cka of: "
										+ secoend_clientCKA + " on port: " + secoend_clientport);
								client_out_to_str = "CHAT_STARTED(" + session + ", " + secoend_client + ")";
								client_out_to_str = encrypt(client_out_to_str, client_connected.getCKA(client));
								client_out_to.writeUTF(client_out_to_str);

								secoend_client_out_to_string = "CHAT_STARTED(" + session + ", " + client + ")";
								secoend_client_out_to_string = encrypt(secoend_client_out_to_string, secoend_clientCKA);
								client_out_toB.writeUTF(secoend_client_out_to_string);
								client_connected.setAvailable(client, false);
								state = "CHAT";
							}
						}
						break;
					case ("CHAT"):
						if (client_in_from_string.contains("END_REQUEST"))
						{
							secoend_client_out_to_string = "END_NOTIF(" + session + ")";
							secoend_client_out_to_string = encrypt(secoend_client_out_to_string, secoend_clientCKA);
							client_out_toB.writeUTF(secoend_client_out_to_string);
							client_connected.setAvailable(client, true);
							state = "IDLE";
							// client_out_toB.flush();
							break;
						} 
						else if (client_in_from_string.contains("END_REC"))
						{
							client_connected.setAvailable(client, true);
							state = "IDLE";
						} 
						else if (client_in_from_string.contains("CHAT("))
						{
							// secoend_client_out_to_string = client_in_from_string;

							secoend_client_out_to_string = encrypt(client_in_from_string, secoend_clientCKA);
							client_out_toB.writeUTF(secoend_client_out_to_string);
							// History chat_history = new History( secoend_client);
							chat_history
									.addMessage(
											client_in_from_string.substring(client_in_from_string.indexOf(",") + 2,
													client_in_from_string.length() - 1),
											client, secoend_client, session);
							// client_out_toB.flush();
						}
						break;

					}

					if (state.equals("DONE")) 
					{
						break;
					}
				}
			}
			catch (Exception e) 
			{
				System.out.println(e);
			}
			try 
			{
				client_connected.removeClient(client);
				connectionSocket.close();
			} catch (IOException ex) {
				System.out.println(ex);
			}

		}

		// Encrypts string using AES
		private String encrypt(String strClearText, byte[] encrypted_cypher_string_key) throws Exception 
		{
			String string_data = "";
			byte[] encrypted_string = null;

			try 
			{
				SecretKeySpec server_key_spec = new SecretKeySpec(encrypted_cypher_string_key, "AES");
				Cipher encripted_cipher = Cipher.getInstance("AES");
				encripted_cipher.init(Cipher.ENCRYPT_MODE, server_key_spec);
				encrypted_string = encripted_cipher.doFinal(strClearText.getBytes());
				string_data = new String(encrypted_string, "ISO-8859-1");

			} 
			catch (Exception e) 
			{
				e.printStackTrace();
				throw new Exception(e);
			}
			return string_data;
		}

		// decrypts string using AES
		private String decrypt(String strEncrypted, byte[] encrypted_cypher_string_key) throws Exception 
		{
			String string_data = "";
			byte[] byteEncrypted = strEncrypted.getBytes("ISO-8859-1");
			try 
			{
				SecretKeySpec server_key_spec = new SecretKeySpec(encrypted_cypher_string_key, "AES");
				Cipher encripted_cipher = Cipher.getInstance("AES");
				encripted_cipher.init(Cipher.DECRYPT_MODE, server_key_spec);
				byte[] decrypted_cipher = encripted_cipher.doFinal(byteEncrypted);
				string_data = new String(decrypted_cipher);

			} 
			catch (Exception e) 
			{
				e.printStackTrace();
				throw new Exception(e);
			}
			return string_data;
		}

	}
}
