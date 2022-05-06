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
    
    private final String clientName;
    private final String clientSecretKey;
    private final String serverName;
    private final int serverPort;
    private byte[] CK_A;
    
    BufferedReader inFromUser;
    
    private DatagramSocket clientSocket;
    private InetAddress IPAddress;
    
    private String state;
    private String sessionID;
    
    ClientServerThread cst = null;
    ClientKeyboardThread ckt = null;
    
    //Sets the class variables and starts the log on process
    public Client(String _clientName, String _clientSecretKey, String _serverName, int _serverPort){
        this.clientName = _clientName;
        this.clientSecretKey = _clientSecretKey;
        this.serverName = _serverName;
        this.serverPort = _serverPort;
        
        //Continues to try to log on until it is successful
        while(!connect()) 
        {
            System.out.println("Try to log on again");
        }
    }
    
    /*Method to connect to the server
     *Returns:  false on an error connecting
     *          true when the process is done
     */
    private boolean connect() {
        //Creates the user input reader
        inFromUser = new BufferedReader(new InputStreamReader(System.in));
        
        try 
        {
            clientSocket = new DatagramSocket();
            IPAddress = InetAddress.getByName(serverName);
            
            String sentence = inFromUser.readLine();
            if(sentence.toUpperCase().equals("LOG ON")) {
                System.out.println("Connecting...");
                //HELLO to the server
                String sendString = "HELLO (" + clientName + ")";
                sendString(sendString);
            
                String response = receiveString().trim();
                //System.out.println("FROM SERVER:" + response);
                
                String[] dataArray = response.split("[()]+");
                for(int a = 0; a < dataArray.length; a ++) 
                {
                    dataArray[a] = dataArray[a].trim().toUpperCase();
                }
                
                //RESPONSE to server
                if(dataArray[0].equals("CHALLENGE"))
                {
                    String xRES = A3(dataArray[1], clientSecretKey);
                    CK_A = A8(dataArray[1], clientSecretKey);
                    //System.out.println(dataArray[1] + clientSecretKey);
                    sendString = "RESPONSE(" + clientName + "," + xRES + ")";
                }
                
                else
                {
                    System.out.println("Error in server response\n" + response);
                    return false;
                }
                
                sendString(sendString);
                byte [] responseBytes = receiveRandCookie();
                //System.out.println("FROM SERVER:" + responseBytes.toString() + " " + responseBytes.length);
                response = decrypt(responseBytes, CK_A);
                //System.out.println("Decrypted FROM SERVER:" + response);
                
                dataArray = response.split("[(), ]+");
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
                    System.out.println("Error in server response\n" + response);
                    return false;
                }
                
            }
            else 
            {
                System.out.println("Please type log on");
                clientSocket.close();
                return false;
            }
            
            clientSocket.close();
            
        }
        catch(Exception e) 
        {
            System.out.println(e);
        }
        return true;
    }
    
    //Sends a string to the UDP server
    private void sendString(String message) throws IOException 
    {
        byte[] sendData = message.getBytes();      
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, serverPort);
        clientSocket.send(sendPacket);
    }
    
    //Receives a string from the UDP server
    //Where the encryption string gets modified, making it error prone
    private String receiveString() throws IOException 
    {
        byte[] receiveData = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
        clientSocket.receive(receivePacket);
        return new String(receivePacket.getData());
    }
    
    private byte [] receiveRandCookie() throws IOException 
    {
        byte[] receiveData = new byte[32];
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
        clientSocket.receive(receivePacket);
        return receivePacket.getData();
    }

    //Performs A3 encryption
    private String A3(String random, String secretKey) 
    {
        String plainText = random + secretKey;
        MessageDigest m = null;
        try 
        {
            m = MessageDigest.getInstance("SHA-1");
        } 
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        m.reset();
        m.update(plainText.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
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
        try 
        {
            m = MessageDigest.getInstance("MD5");
        } 
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        m.reset();
        m.update(CK_A.getBytes());
        byte[] digest = m.digest();
        return digest;
    }
    
    //Used for UDP currently
    private String encrypt(String strClearText,byte[] digest) throws Exception
    {
        String strData="";
		byte [] encrypted = null;
		
		try 
		{
			SecretKeySpec skeyspec=new SecretKeySpec(digest,"AES");
			Cipher cipher=Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
			encrypted=cipher.doFinal(strClearText.getBytes());
			strData=new String(encrypted, "ISO-8859-1");
			
		} 
		catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e);
		}
		return strData;
    }
    
    //Used for TCP connections, does not currently work for UDP
    private String encrypt2(String strClearText,byte[] digest) throws Exception
    {
        String strData="";
        byte [] encrypted = null;

        try 
        {
            SecretKeySpec skeyspec=new SecretKeySpec(digest,"AES");
            Cipher cipher=Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
            encrypted=cipher.doFinal(strClearText.getBytes());
            strData=new String(encrypted, "ISO-8859-1");

        } 
        catch (Exception e) 
        {
            e.printStackTrace();
            throw new Exception(e);
        }
        return strData;
    }
    
    //Used for UDP currently
    private String decrypt(byte[] strEncrypted, byte[] digest) throws Exception
    {
		String strData="";
		byte[] byteEncrypted = strEncrypted;
		try 
		{
			SecretKeySpec skeyspec=new SecretKeySpec(digest,"AES");
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

        } 
        catch (Exception e) 
        {
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
            
            cst = new ClientServerThread(this, inFromServer, CK_A);
            Thread thread = new Thread(cst);
            thread.start();
            
            ckt = new ClientKeyboardThread(this, outToServer, CK_A);
            Thread thread2 = new Thread(ckt);
            thread2.start();
        }catch(Exception e) {
            System.out.println(e);
        }
    }
    
    public void setState(String state)
    {
        this.state = state;
    }
    
    public String getState() 
    {
        return state;
    }
    
    public void setSessionID(String session) 
    {
        this.sessionID = session;
    }
    
    public String getSessionID()
    {
        return sessionID;
    }
    
    public void startChat(String message)
    {
        ckt.startChat(message);
    }
    
    public void endChat(String message) 
    {
        ckt.endChat(message);
    }
    
    public void stop()
    {
        cst.stopIt();
    }
    public String getClientName()
    {
    	return this.clientName;
    }
    
    public static void main(String args[])
    {
        Client client = null;//new Client("A","1234","localhost",9879);
        
        if(args.length != 4)
            System.out.println("Use correct input, client name, client key, host name, port number");
        else
            client = new Client(args[0], args[1], args[2], Integer.parseInt(args[3]));
    }
    
}

class ConnectedClients 
{
    private HashMap<String, String> secretKeys;
    private HashMap<String, String> xRES;
    private HashMap<String, byte[]> CK_A;
    private HashMap<String, Integer> ports;
    private HashMap<String, DataOutputStream> streams;
    private HashMap<String, Boolean> available;
    private int session;
    
    public ConnectedClients() 
    {
        secretKeys = new HashMap<>();
        xRES = new HashMap<>();
        CK_A = new HashMap<>();
        ports = new HashMap<>();
        streams = new HashMap<>();
        available = new HashMap<>();
    }
    
    public void addSecretKey(String key, String value) 
    {
        secretKeys.put(key, value);
    }
    
    public String getSecretKey(String key)
    {
        return secretKeys.get(key);
    }
    
    public void addXRES(String key, String string)
    {
        xRES.put(key, string);
    }
    
    public String getXRES(String key) 
    {
        return xRES.get(key);
    }
    
    public void addCKA(String key, byte[] bs)
    {
        CK_A.put(key, bs);
    }
    
    public byte[] getCKA(String key) 
    {
        return CK_A.get(key);
    }
    
    public void addPort(String key, Integer port) 
    {
        ports.put(key, port);
    }
    
    public int getPort(String key)
    {
        return ports.get(key);
    }
    
    public void addStream(String key, DataOutputStream dos) 
    {
        streams.put(key, dos);
    }
    
    public DataOutputStream getStream(String key) 
    {
        return streams.get(key);
    }
    
    public void addAvailable(String key, Boolean bool) 
    {
        available.put(key, bool);
    }
    
    public void setAvailable(String key, Boolean bool) 
    {
        available.replace(key, bool);
    }
    
    public Boolean getAvailable(String key) 
    {
        return available.get(key);
    }
    
    public int getSession() 
    {
        return session++;
    }

    public void removeClient(String key)
    {
        xRES.remove(key);
        CK_A.remove(key);
    }
    
}

class History 
{
    
    public String filePath;
    public String[] parts;
    
    private HashMap<Integer, ArrayList<String>> history; 
    
    public History(String filePath)
    {
        this.filePath = filePath;
    }
    
    public History() 
    {
        history = new HashMap<>();
    }

    public void addMessage(String msg, String sender, String receiver, int session)
    {

        String save = session + " From: " + sender + " To: " + receiver + " " + msg;

        if(history.get(session) != null) 
        {
            System.out.println("TRUE");
            history.get(session).add(save);
        }
        else 
        {
            System.out.println("FLASE");
            history.put(session, new ArrayList<String>());
            history.get(session).add(save);
        }
    }
    
    public ArrayList<String> getHistory(String clientA, String clientB) 
    {
        ArrayList<String> arr = new ArrayList<>();
        for(Entry<Integer, ArrayList<String>> s : history.entrySet()) 
        {
            for(String str : s.getValue()) 
            {
                if(str.contains("From: " + clientA) && str.contains("To: " + clientB) || str.contains("From: " + clientB) && str.contains("To: " + clientA)) 
                {
                    arr.add(str);
                }
            }
        }
        return arr;
    }
        
        
    public String printToconsole()
    {
        
        String returnStr = "";
        for(Entry<Integer, ArrayList<String>> s : history.entrySet()) 
        {
            for(String str : s.getValue()) 
            {
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

class ClientKeyboardThread extends Thread 
{
    Client client;
    DataOutputStream outToServer;
    BufferedReader inFromUser;
    byte[] CK_A;
    
    public ClientKeyboardThread(Client client, DataOutputStream outToServer, byte[] CK_A)
    {
        this.client = client;
        this.outToServer = outToServer;
        this.inFromUser = new BufferedReader(new InputStreamReader(System.in));
        this.CK_A = CK_A;
    }
    
    public void run() 
    {
        String outToServerString;
        while(true)
        {
            try 
            {
                String line = inFromUser.readLine();
                switch(client.getState()) 
                {
                    case ("IDLE"):
                        if(line.toUpperCase().equals("LOG OFF")) 
                        {
                            outToServerString = encrypt2(line, CK_A);
                            outToServer.writeUTF(outToServerString);
                            outToServer.flush();
                            outToServer.close();
                            inFromUser.close();
                            client.stop();
                            break;
                        }
                        else if(line.contains("Chat")) 
                        {
                            client.setState("REQUEST");
                            outToServerString = "CHAT_REQUEST(" + line.split("[ ]")[1] + ")";
                            outToServerString = encrypt2(outToServerString, CK_A);
                            outToServer.writeUTF(outToServerString);
                            outToServer.flush();
                        }
                        else if(line.toUpperCase().contains("HISTORY")) {                          
                                outToServerString = encrypt2("HISTORY_REQUEST(" + line.split("[ ]")[1] + ")", CK_A);
                                outToServer.writeUTF(outToServerString);
                                outToServer.flush();
                                break;
                        }
                        else
                        {
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
                            //History history = new History(client.getClientName());
                            //history.addMessage(line, client.getClientName());
                        }
                        break;
                }
            } 
            
            catch(Exception e)
            {
                System.out.println(e);
                break;
            }
        }
    }
    
    public void startChat(String message) {
        try {
            client.setState("CHAT");
            String outToServerString = message;
            outToServerString = encrypt2(outToServerString, CK_A);
            outToServer.writeUTF(outToServerString);
            outToServer.flush();
        }
        
        catch(Exception e)
        {
            System.out.println(e);
        }
    }
    
    public void endChat(String message) {
        try {
            client.setState("IDLE");
            String outToServerString = message.replace("END_NOTIF", "END_REC");
            outToServerString = encrypt2(outToServerString, CK_A);
            outToServer.writeUTF(outToServerString);
            outToServer.flush();
            
        }
        
        catch(Exception e) {
            System.out.println(e);
        }
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

        } 
        
        catch (Exception e) {
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
    
    public ClientServerThread(Client client, DataInputStream inFromServer, byte[] CK_A)
    {
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
        }
        
        catch(Exception e) {
            System.out.println(e);
        }
    }
    
    //Used for TCP connections, does not currently work for UDP
    private String decrypt2(String strEncrypted, byte[] digest) throws Exception
    {
        String strData="";
        byte[] byteEncrypted = strEncrypted.getBytes("ISO-8859-1");
        
        SecretKeySpec skeyspec=new SecretKeySpec(digest,"AES");
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeyspec);
        byte[] decrypted=cipher.doFinal(byteEncrypted);
        strData = new String(decrypted);

        return strData;
    }
}
