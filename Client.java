
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/*
 * Client class for the server based chat project
 * Handles the connection phase then create a thread for listening to the keyboard and server input
 */

public class Client {

	class ClientServerThread extends Thread {
	    Client client;
	    DataInputStream inputServer;
	    byte[] CK_A;
	    
	    public ClientServerThread(Client client, DataInputStream inputServer, byte[] CK_A) {
	        this.client = client;
	        this.inputServer = inputServer;
	        this.CK_A = CK_A;
	    }
	    
	    public void run() {
	        while(true) 
	        {
	            try 
	            {
	                String inputServerMsg = inputServer.readUTF();
	                inputServerMsg = decrypt2(inputServerMsg, CK_A);
	                
	                if(client.getState().equalsIgnoreCase("IDLE"))
	                {
	                	if(inputServerMsg.contains("CHAT_STARTED"))
	                	{
                            System.out.println("Chat started with " + inputServerMsg.split("[(), ]+")[2]);
                            client.setSessionID(inputServerMsg.split("[(), ]+")[1]);
                            client.setState("CHAT");
                            client.startChat(inputServerMsg);
                        } else if(inputServerMsg.contains("HISTORY_RESP")) 
                        {
                            System.out.println(inputServerMsg.substring(inputServerMsg.indexOf("(") + 1, inputServerMsg.length() - 1));
                        }
	                }
	                else if(client.getState().equalsIgnoreCase("REQUEST"))
	                {
	                	if(inputServerMsg.contains("UNREACHABLE")) 
	                	{
                            System.out.println("Client " + inputServerMsg.split("[()]")[1] + " is currently unreachable");
                            client.setState("IDLE");
                        }else {
                            System.out.println("Chat started with " + inputServerMsg.split("[(), ]+")[2]);
                            client.setSessionID(inputServerMsg.split("[(), ]+")[1]);
                            client.setState("CHAT");
                        }
	                }
	                else if(client.getState().equalsIgnoreCase("CHAT"))
	                {
	                	if(inputServerMsg.contains("END_NOTIF")) 
	                	{
                            System.out.println("Chat Ended");
                            client.endChat(inputServerMsg);
                            client.setState("IDLE");
                        }
	                	else 
                        {
                            String s = inputServerMsg.substring(inputServerMsg.indexOf(",") + 2, inputServerMsg.length() - 1);
                            System.out.println(s);
                        }
	                }
	            } 
	            catch(Exception e) 
	            {
	                System.out.println(e);
	                break;
	            }
	        }
	    }
	    
	    public void stopIt() throws Exception 
	    {
	    	inputServer.close();
	    }
	    //Used for TCP connections, does not currently work for UDP
	    private String decrypt2(String strEncrypted, byte[] hash) throws Exception
	    {
	        String strData="";
	        byte[] byteEncrypted = strEncrypted.getBytes("ISO-8859-1");
	        try 
	        {
	            SecretKeySpec skeyspec=new SecretKeySpec(hash,"AES");
	            Cipher cipher=Cipher.getInstance("AES");
	            cipher.init(Cipher.DECRYPT_MODE, skeyspec);
	            byte[] decrypted=cipher.doFinal(byteEncrypted);
	            strData = new String(decrypted);
	
	        } 
	        catch (Exception e) 
	        {
	            e.printStackTrace();
	            throw new Exception(e);
	        }
	        return strData;
	    }
	}

    String name;
    String secretKey;
    String serverName;
    int serverPort;
    byte[] CK_A;
    
    BufferedReader inFromUser;
    
    DatagramSocket socket;
    InetAddress IP;
    
    String state;
    String sessionID;
    
    ClientServerThread serverThread = null;
    ClientKeyboardThread keyboardThread = null;
    
    //Sets the class variables and starts the log on process
    public Client(String name, String secretKey, String serverName, int port) throws Exception
    {
        this.name = name;
        this.secretKey = secretKey;
        this.serverName = serverName;
        this.serverPort = port;
        
        //Continues to try to log on until it is successful
        while(connect() == false) 
        {
            System.out.println("Log in failed. Please try again:");
        }
    }
    
    /*Method to connect to the server
     *Returns:  false on an error connecting
     *          true when the process is done
     */
    public boolean connect() throws Exception
    {
        //Creates the user input reader
        inFromUser = new BufferedReader(new InputStreamReader(System.in));
        
            socket = new DatagramSocket();
            IP = InetAddress.getByName(serverName);
            
            String sentence = inFromUser.readLine();
            if(sentence.equalsIgnoreCase("LOG ON")) 
            {
                System.out.println("Connecting...");
                String sendToServer = "HELLO (" + name + ")";	//sends hello plus client's name to server
                sendString(sendToServer);
            
                String serverResponse = receiveString().trim(); //server's response
                //System.out.println("FROM SERVER:" + response);
                
                String[] dataArray = serverResponse.split("[()]+");
                for(int a = 0; a < dataArray.length; a ++) 
                {
                    dataArray[a] = dataArray[a].trim().toUpperCase();
                }
                
                //RESPONSE to server
                if(dataArray[0].equalsIgnoreCase("CHALLENGE")) 
                {
                    String xRES = A3(dataArray[1], secretKey);
                    CK_A = A8(dataArray[1], secretKey);
                    sendToServer = "RESPONSE(" + name + ", " + xRES + ")";
                }
                else 
                {
                    System.out.println("Server Response Error: " + serverResponse);
                    return false;
                }
                
                sendString(sendToServer);
                byte [] responseBytes = receiveRandCookie();
                serverResponse = decrypt(responseBytes, CK_A);
                
                dataArray = serverResponse.split("[(), ]+");
                for(int a = 0; a < dataArray.length; a ++) 
                {
                    dataArray[a] = dataArray[a].trim().toUpperCase();
                }
                
                //Switches to TCP
                if(dataArray[0].equals("AUTH_SUCCESS")) 
                {
                    runTCPClient(dataArray[1], Integer.parseInt(dataArray[2]));
                }
                else 
                {
                    System.out.println("Error in server response\n" + serverResponse);
                    return false;
                }
                
            }
            else 
            {
                System.out.println("Forgot to LOG ON");
                socket.close();
                return false;
            }
            socket.close();
        return true;
    }
    
    //Sends a string to the UDP server
    void sendString(String message) throws IOException 
    {
        byte[] sendData = message.getBytes();      
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IP, serverPort);
        socket.send(sendPacket);
    }
    
    //Receives a string from the UDP server
    //Where the encryption string gets modified, making it error prone
    String receiveString() throws IOException {
        byte[] dataFromServer = new byte[2048];  //max 2 KB message from server
        DatagramPacket packetReceived = new DatagramPacket(dataFromServer, dataFromServer.length);
        socket.receive(packetReceived);
        return new String(packetReceived.getData());
    }
    
    byte [] receiveRandCookie() throws IOException {
        byte[] receiveData = new byte[16];
        DatagramPacket packetReceived = new DatagramPacket(receiveData, receiveData.length);
        socket.receive(packetReceived);
        return packetReceived.getData();
    }

    //Performs A3 encryption
    String A3(String random, String secretKey) {
        String plainText = random + secretKey;
        MessageDigest m = null;
        try {
            m = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        m.reset();
        m.update(plainText.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        String strData = bigInt.toString(16);
        //Padding
        while(strData.length() < 32 ){
            strData = "0"+strData;
        }
        return strData;
    }
    
    //Generate the ciphering key
    //Generated Key needs to be 16 byte length
    private byte[] A8(String ran, String strKey){
        String CK_A = ran + strKey;
        MessageDigest m = null;
        try {
            m = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        m.reset();
        m.update(CK_A.getBytes());
        byte[] digest = m.digest();
        return digest;
    }
    
    //Used for UDP currently
    private String encrypt(String strClearText,byte[] digest) throws Exception{
        String strData="";
		byte [] encrypted = null;
		
		try {
			SecretKeySpec skeyspec=new SecretKeySpec(digest,"AES");
			Cipher cipher=Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
			encrypted=cipher.doFinal(strClearText.getBytes());
			strData=new String(encrypted, "ISO-8859-1");
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e);
		}
		return strData;
    }
    
    //Used for TCP connections, does not currently work for UDP
    private String encrypt2(String strClearText,byte[] digest) throws Exception{
        String strData="";
        byte [] encrypted = null;

        try {
            SecretKeySpec skeyspec=new SecretKeySpec(digest,"AES");
            Cipher cipher=Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
            encrypted=cipher.doFinal(strClearText.getBytes());
            strData=new String(encrypted, "ISO-8859-1");

        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
        }
        return strData;
    }
    
    //Used for UDP currently
    private String decrypt(byte[] strEncrypted, byte[] digest) throws Exception{
		String strData="";
		byte[] byteEncrypted = strEncrypted;
		try {
			SecretKeySpec skeyspec=new SecretKeySpec(digest,"AES");
			Cipher cipher=Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, skeyspec);
			byte[] decrypted=cipher.doFinal(byteEncrypted);
			strData = new String(decrypted);
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e);
		}
		return strData;
    }
    
    //Used for TCP connections, does not currently work for UDP
    private String decrypt2(String strEncrypted, byte[] digest) throws Exception{
        String strData="";
        byte[] byteEncrypted = strEncrypted.getBytes("ISO-8859-1");
        try {
            SecretKeySpec skeyspec=new SecretKeySpec(digest,"AES");
            Cipher cipher=Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, skeyspec);
            byte[] decrypted=cipher.doFinal(byteEncrypted);
            strData = new String(decrypted);

        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
        }
        return strData;
    }
    
    //Runs the TCP client
    private void runTCPClient(String cookie, int port) {
        String outToServerString;
        String inputServerMsg;
        
        try {
            //System.out.println("Connecting to: " + port);
            Socket TCPClientSocket = new Socket(serverName, port);
            DataOutputStream outToServer = new DataOutputStream(TCPClientSocket.getOutputStream());
            DataInputStream inputServer = new DataInputStream(new BufferedInputStream(TCPClientSocket.getInputStream()));
            
            outToServerString = "CONNECT(" + cookie + ")";
            outToServerString = encrypt2(outToServerString, CK_A);
            outToServer.writeUTF(outToServerString);
            outToServer.flush();
            
            inputServerMsg = inputServer.readUTF();
            //System.out.println("FROM SERVER: " + inputServerMsg);
            inputServerMsg = decrypt2(inputServerMsg, CK_A);
            //System.out.println("Decrypted FROM SERVER: " + inputServerMsg);
            setState("IDLE");
            
            System.out.println("Connected");
            
            serverThread = new ClientServerThread(this, inputServer, CK_A);
            Thread thread = new Thread(serverThread);
            thread.start();
            
            keyboardThread = new ClientKeyboardThread(this, outToServer, CK_A);
            Thread thread2 = new Thread(keyboardThread);
            thread2.start();
        }catch(Exception e) {
            System.out.println(e);
        }
    }
    
    public void setState(String state) {
        this.state = state;
    }
    public String getState() {
        return state;
    }
    public void setSessionID(String session) {
        this.sessionID = session;
    }
    public String getSessionID() {
        return sessionID;
    }
    public void startChat(String message) {
        keyboardThread.startChat(message);
    }
    public void endChat(String message) {
        keyboardThread.endChat(message);
    }
    public void stop() throws Exception {
        serverThread.stopIt();
    }
    public String getClientName(){
    	return this.name;
    }
    
    public static void main(String args[]){
        Client client = null;// e.g. new Client("A","1234","localhost",9879); 
        
        if(args.length != 4)
            System.out.println("Use correct input: client name, client key, host name, port number");
		else
		{
			try 
        	{
				client = new Client(args[0], args[1], args[2], Integer.parseInt(args[3]));
			} 
        	catch (Exception e) {
				System.out.println(e);
			}
		}
    }
}
