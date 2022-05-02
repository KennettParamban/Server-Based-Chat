import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.io.DataOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;

/*
 * Client class for the server based chat project
 * Handles the connection phase then create a thread for listening to the keyboard and server input
 */

public class Client {
    
    String name;
    String secretKey;
    String serverName;
    int port;
    byte[] CK_A;
    
    BufferedReader userInput;
    
    DatagramSocket socket;
    InetAddress IP;
    
    String state;
    String sessionID;
    
    ClientServerThread serverThread = null;
    ClientKeyboardThread keyboardThread = null;
    
    //Sets the class variables and starts the log on process
    public Client(String name, String secretKey, String serverName, int port){
        this.name = name;
        this.secretKey = secretKey;
        this.serverName = serverName;
        this.port = port;
        
        //Continues to try to log on until it is successful
        try {
	        while(connect() == false) {
	            System.out.println("Log in fauled. Please try again: ");
	        }
        }
        catch(Exception e)
        {
        	System.out.println(e);
        	}
    }
    
    //Tries to connect to server and returns false if error
    private boolean connect() throws Exception{
        //Used to read user input
        userInput = new BufferedReader(new InputStreamReader(System.in));
        
        socket = new DatagramSocket();
        IP = InetAddress.getByName(serverName);
        
        String sentence = userInput.readLine();
        if(sentence.equalsIgnoreCase("Log on")) {
            System.out.println("Connecting...");
            //sends "HELLO" and client name to server
            String sendToServer = "HELLO (" + name + ")";
            sendString(sendToServer);
            String serverResponse = receiveString().trim();
            
            String[] dataArray = serverResponse.split("[()]+");
            for(int a = 0; a < dataArray.length; a ++) {
                dataArray[a] = dataArray[a].trim().toUpperCase();
            }
            //RESPONSE to server
            if(dataArray[0].equalsIgnoreCase("Challenge")) {
                String xRES = A3(dataArray[1], secretKey);
                CK_A = A8(dataArray[1], secretKey);
                //System.out.println(dataArray[1] + secretKey);
                sendToServer = "RESPONSE(" + name + "," + xRES + ")";
            }
            else {
                System.out.println("Server response error: " + serverResponse);
                return false;
            }
            
            sendString(sendToServer);
            byte [] responseBytes = receiveRandCookie();
            serverResponse = decrypt(responseBytes, CK_A);
            
            dataArray = serverResponse.split("[(), ]+");
            for(int a = 0; a < dataArray.length; a ++) {
                dataArray[a] = dataArray[a].trim().toUpperCase();
            }
            
            //Switches to TCP
            if(dataArray[0].equalsIgnoreCase("AUTH_SUCCESS")) {
                runTCPClient(dataArray[1], Integer.parseInt(dataArray[2]));
            }
            else {
                System.out.println("Error in server response\n" + serverResponse);
                return false;
            }
        }
        else {
            System.out.println("Forgot to Log on");
            socket.close();
            return false;
        }
        socket.close();
        return true;
    }
    
    //Sends a string to the UDP server
    private void sendString(String msg) throws IOException {
        byte[] sendData = msg.getBytes();      
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IP, port);
        socket.send(sendPacket);
    }
    
    //Receives a string from the UDP server
    //Where the encryption string gets modified, making it error prone
    private String receiveString() throws IOException {
        byte[] dataFromServer = new byte[1024];
        DatagramPacket packetReceived = new DatagramPacket(dataFromServer, dataFromServer.length);
        socket.receive(packetReceived);
        return new String(packetReceived.getData());
    }
    
    private byte [] receiveRandCookie() throws IOException {
        byte[] dataFromServer = new byte[32];
        DatagramPacket packetReceived = new DatagramPacket(dataFromServer, dataFromServer.length);
        socket.receive(packetReceived);
        return packetReceived.getData();
    }

    //Performs A3 encryption
    private String A3(String rand, String secretKey) {
        String plainText = rand + secretKey;
        MessageDigest m = null;
        try 
        {
            m = MessageDigest.getInstance("SHA-1");
        } 
        catch (NoSuchAlgorithmException e) 
        {
            System.out.println(e);
        }
        m.reset();
        m.update(plainText.getBytes());
        byte[] hash = m.digest();
        BigInteger bigInt = new BigInteger(1,hash);
        String strData = bigInt.toString(16);
        
        //Padding
        while(strData.length() < 32 )
        {
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
        byte[] hash = m.digest();
        return hash;
    }
    
    //Used for UDP currently
    private String encrypt(String strClearText,byte[] hash) throws Exception{
        String strData="";
		byte [] encrypted = null;
		
		try {
			SecretKeySpec skeyspec=new SecretKeySpec(hash,"AES");
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
    private String encrypt2(String strClearText,byte[] hash) throws Exception{
        String strData="";
        byte [] encrypted = null;

        try {
            SecretKeySpec skeyspec=new SecretKeySpec(hash,"AES");
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
    
    private String decrypt(byte[] strEncrypted, byte[] hash) throws Exception{
		String strData="";
		byte[] byteEncrypted = strEncrypted;
		try {
			SecretKeySpec skeyspec=new SecretKeySpec(hash,"AES");
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
    private String decrypt2(String strEncrypted, byte[] hash) throws Exception{
        String strData="";
        byte[] byteEncrypted = strEncrypted.getBytes("ISO-8859-1");
        try {
            SecretKeySpec skeyspec=new SecretKeySpec(hash,"AES");
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
        String inFromServerString;
        
        try {
            //System.out.println("Connecting to: " + port);
            Socket TCPClientSocket = new Socket(serverName, port);
            DataOutputStream outToServer = new DataOutputStream(TCPClientSocket.getOutputStream());
            DataInputStream inFromServer = new DataInputStream(new BufferedInputStream(TCPClientSocket.getInputStream()));
            
            outToServerString = "CONNECT(" + cookie + ")";
            outToServerString = encrypt2(outToServerString, CK_A);
            outToServer.writeUTF(outToServerString);
            outToServer.flush();
            
            inFromServerString = inFromServer.readUTF();
            //System.out.println("FROM SERVER: " + inFromServerString);
            inFromServerString = decrypt2(inFromServerString, CK_A);
            //System.out.println("Decrypted FROM SERVER: " + inFromServerString);
            setState("IDLE");
            
            System.out.println("Connected");
            
            serverThread = new ClientServerThread(this, inFromServer, CK_A);
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
    public void setSessionID(String session) {
        this.sessionID = session;
    }
    
    public String getState() {
        return state;
    }
    public String getSessionID() {
        return sessionID;
    }
    public String getName(){
    	return this.name;
    }
    
    public void startChat(String msg) {
        keyboardThread.startChat(msg);
    }
    public void endChat(String msg) {
        keyboardThread.endChat(msg);
    }
    
    public void stop() {
        serverThread.stopIt();
    }
    
    
    public static void main(String args[]){
        Client client = null;//new Client("A","1234","localhost",9879);
        
        if(args.length != 4)
            System.out.println("Use correct input, client name, client key, host name, port number");
        else
            client = new Client(args[0], args[1], args[2], Integer.parseInt(args[3]));
    }
    
}

class ConnectedClients {
    private HashMap<String, String> secretKeys;
    private HashMap<String, String> xRES;
    private HashMap<String, byte[]> CK_A;
    private HashMap<String, Integer> ports;
    private HashMap<String, DataOutputStream> streams;
    private HashMap<String, Boolean> available;
    private int session;
    
    public ConnectedClients() {
        secretKeys = new HashMap<>();
        xRES = new HashMap<>();
        CK_A = new HashMap<>();
        ports = new HashMap<>();
        streams = new HashMap<>();
        available = new HashMap<>();
    }
    
    public void addSecretKey(String key, String value) {
        secretKeys.put(key, value);
    }
    
    public String getSecretKey(String key) {
        return secretKeys.get(key);
    }
    
    public void addXRES(String key, String string) {
        xRES.put(key, string);
    }
    
    public String getXRES(String key) {
        return xRES.get(key);
    }
    
    public void addCKA(String key, byte[] bs) {
        CK_A.put(key, bs);
    }
    
    public byte[] getCKA(String key) {
        return CK_A.get(key);
    }
    
    public void addPort(String key, Integer port) {
        ports.put(key, port);
    }
    
    public int getPort(String key) {
        return ports.get(key);
    }
    
    public void addStream(String key, DataOutputStream dos) {
        streams.put(key, dos);
    }
    
    public DataOutputStream getStream(String key) {
        return streams.get(key);
    }
    
    public void addAvailable(String key, Boolean bool) {
        available.put(key, bool);
    }
    
    public void setAvailable(String key, Boolean bool) {
        available.replace(key, bool);
    }
    
    public Boolean getAvailable(String key) {
        return available.get(key);
    }
    
    public int getSession() {
        return session++;
    }

    public void removeClient(String key) {
        xRES.remove(key);
        CK_A.remove(key);
    }
    
}

class History {
    
    public String filePath;
    public String[] parts;
    
    private HashMap<Integer, ArrayList<String>> history; 
    
    public History(String filePath){
        this.filePath = filePath;
    }
    
    public History() {
        history = new HashMap<>();
    }

    public void addMessage(String msg, String sender, String receiver, int session){

        String save = session + " From: " + sender + " To: " + receiver + " " + msg;

        if(history.get(session) != null) {
            System.out.println("TRUE");
            history.get(session).add(save);
        }
        else {
            System.out.println("FLASE");
            history.put(session, new ArrayList<String>());
            history.get(session).add(save);
        }
    }
    
    public ArrayList<String> getHistory(String clientA, String clientB) {
        ArrayList<String> arr = new ArrayList<>();
        for(Entry<Integer, ArrayList<String>> s : history.entrySet()) {
            for(String str : s.getValue()) {
                if(str.contains("From: " + clientA) && str.contains("To: " + clientB) || str.contains("From: " + clientB) && str.contains("To: " + clientA)) {
                    arr.add(str);
                }
            }
        }
        return arr;
    }
        
        
    public String printToconsole(){
        
        String returnStr = "";
        for(Entry<Integer, ArrayList<String>> s : history.entrySet()) {
            for(String str : s.getValue()) {
                returnStr += str + "\n";
            }
            returnStr += "\n";
        }
        return returnStr;
        
        
        /*String s=null;
	String line = null;
	try {
		s = new String(Files.readAllBytes(Paths.get(filePath)));
	}
	catch (IOException e) {
		e.printStackTrace();}
	return s;*/
    }
}

class ClientKeyboardThread extends Thread {
    Client client;
    DataOutputStream outToServer;
    BufferedReader userInput;
    byte[] CK_A;
    
    public ClientKeyboardThread(Client client, DataOutputStream outToServer, byte[] CK_A) {
        this.client = client;
        this.outToServer = outToServer;
        this.userInput = new BufferedReader(new InputStreamReader(System.in));
        this.CK_A = CK_A;
    }
    
    public void run() {
        String outToServerString;
        while(true) {
            try {
                String line = userInput.readLine();
                switch(client.getState()) {
                    case ("IDLE"):
                        if(line.toUpperCase().equals("LOG OFF")) {
                            outToServerString = encrypt2(line, CK_A);
                            outToServer.writeUTF(outToServerString);
                            outToServer.flush();
                            outToServer.close();
                            userInput.close();
                            client.stop();
                            break;
                        }else if(line.contains("Chat")) {
                            client.setState("REQUEST");
                            outToServerString = "CHAT_REQUEST(" + line.split("[ ]")[1] + ")";
                            outToServerString = encrypt2(outToServerString, CK_A);
                            outToServer.writeUTF(outToServerString);
                            outToServer.flush();
                        }else if(line.toUpperCase().contains("HISTORY")) {                          
                                outToServerString = encrypt2("HISTORY_REQUEST(" + line.split("[ ]")[1] + ")", CK_A);
                                outToServer.writeUTF(outToServerString);
                                outToServer.flush();
                                break;
                        }else {
                            System.out.println("Please type Log Off or Chat [Client-ID] or History [Client-ID]");
                        }
                        break;
                    case ("CHAT"):
                        if(line.toUpperCase().equals("END CHAT")) {
                            client.setState("IDLE");
                            outToServerString = encrypt2("END_REQUEST(" + client.getSessionID() + ")", CK_A);
                            outToServer.writeUTF(outToServerString);
                            outToServer.flush();
                            break;
                        }
                        else {
                            outToServerString = encrypt2("CHAT(" + client.getSessionID() + ", " + line + ")", CK_A);
                            outToServer.writeUTF(outToServerString);
                            outToServer.flush();
                        }
                        break;
                }
            } catch(Exception e){
                System.out.println(e);
                break;
            }
        }
    }
    
    public void startChat(String msg) {
        try {
            client.setState("CHAT");
            String outToServerString = msg;
            outToServerString = encrypt2(outToServerString, CK_A);
            outToServer.writeUTF(outToServerString);
            outToServer.flush();
        }catch(Exception e) {
            System.out.println(e);
        }
    }
    
    public void endChat(String msg) {
        try {
            client.setState("IDLE");
            String outToServerString = msg.replace("END_NOTIF", "END_REC");
            outToServerString = encrypt2(outToServerString, CK_A);
            outToServer.writeUTF(outToServerString);
            outToServer.flush();
            
        }catch(Exception e) {
            System.out.println(e);
        }
    }
    
        //Used for TCP connections, does not currently work for UDP
    private String encrypt2(String strClearText,byte[] hash) throws Exception{
        String strData="";
        byte [] encrypted = null;

        try {
            SecretKeySpec skeyspec=new SecretKeySpec(hash,"AES");
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
}

class ClientServerThread extends Thread {
    Client client;
    DataInputStream inFromServer;
    byte[] CK_A;
    
    public ClientServerThread(Client client, DataInputStream inFromServer, byte[] CK_A) {
        this.client = client;
        this.inFromServer = inFromServer;
        this.CK_A = CK_A;
        //System.out.println(CK_A);
    }
    
    public void run() {
        while(true) {
            try {
                String inFromServerString = inFromServer.readUTF();
                //System.out.println("FROM SERVER: " + inFromServerString);
                inFromServerString = decrypt2(inFromServerString, CK_A);
                //System.out.println("Decrypted FROM SERVER: " + inFromServerString);
                
                switch(client.getState()) {
                    case ("IDLE"):
                        if(inFromServerString.contains("CHAT_STARTED")){
                            System.out.println("Chat started with " + inFromServerString.split("[(), ]+")[2]);
                            client.setSessionID(inFromServerString.split("[(), ]+")[1]);
                            client.setState("CHAT");
                            client.startChat(inFromServerString);
                        } else if(inFromServerString.contains("HISTORY_RESP")) {
                            System.out.println(inFromServerString.substring(inFromServerString.indexOf("(") + 1, inFromServerString.length() - 1));
                        }
                        
                        break;
                    case ("REQUEST"):
                        if(inFromServerString.contains("UNREACHABLE")) {
                            System.out.println("Client " + inFromServerString.split("[()]")[1] + " is currently unreachable");
                            client.setState("IDLE");
                        }else {
                            System.out.println("Chat started with " + inFromServerString.split("[(), ]+")[2]);
                            client.setSessionID(inFromServerString.split("[(), ]+")[1]);
                            client.setState("CHAT");
                        }
                        break;
                    case ("CHAT"):
                        if(inFromServerString.contains("END_NOTIF")) {
                            System.out.println("Chat Ended");
                            client.endChat(inFromServerString);
                            client.setState("IDLE");
                        }else {
                            String s = inFromServerString.substring(inFromServerString.indexOf(",") + 2, inFromServerString.length() - 1);
                            System.out.println(s);
                        }
                        break;
                }
            } catch(Exception e) {
                System.out.println(e);
                break;
            }
        }
    }
    
    public void stopIt() {
        try {
            inFromServer.close();
        }catch(Exception e) {
            System.out.println(e);
        }
    }
    
    //Used for TCP connections, does not currently work for UDP
    private String decrypt2(String strEncrypted, byte[] hash) throws Exception{
        String strData="";
        byte[] byteEncrypted = strEncrypted.getBytes("ISO-8859-1");
        try {
            SecretKeySpec skeyspec=new SecretKeySpec(hash,"AES");
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
}
