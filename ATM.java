import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ATM {

    private String domain;
    private int port;
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private BufferedReader stdIn;

    public ATM(String domain, int port){
        this.domain = domain;
        this.port = port;
        stdIn = new BufferedReader(new InputStreamReader(System.in));
    }

    public void connect() throws IOException{
        socket = new Socket(domain, port);
        out = new PrintWriter(socket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    private SecretKey generateSymmetricKey() throws Exception{
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private byte[] encryptWIthPublicKey(byte[] plaintext, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    private byte[] encryptWithSymmetricKey(String plaintext, SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    private PublicKey loadPublicKey() throws Exception{
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get("publicKey"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public void run() throws Exception{
        while (true){
            System.out.print("Enter your ID: ");
            String id = stdIn.readLine();
            

            System.out.print("Enter your Password: ");
            String password = stdIn.readLine();

            PublicKey bankPublicKey = loadPublicKey();
            SecretKey symmetricKey = generateSymmetricKey();
            byte[] encryptedSymmetricKey = encryptWIthPublicKey(symmetricKey.getEncoded(), bankPublicKey);
            byte[] encryptedCredentials = encryptWithSymmetricKey(id + ":" + password, symmetricKey);
            out.println(Base64.getEncoder().encodeToString(encryptedSymmetricKey));
            out.println(Base64.getEncoder().encodeToString(encryptedCredentials));

            //out.println(id);
            //out.println(password);

            String response = in.readLine();
            System.out.println(response);

            if (response.equals("ID and password are correct")){
                boolean exit = false;

                while (!exit){
                    System.out.println("Please select one of the following actions (enter 1,2, or 3):");
                    System.out.println("1. Transfer money");
                    System.out.println("2. Check account balance");
                    System.out.println("3. Exit");

                    String choice = stdIn.readLine();
                    out.println(choice);

                    switch (choice){
                        case "1":
                            while (true){
                                System.out.println("Pease select an account (enter 1 or 2):");
                                System.out.println("1. Savings");
                                System.out.println("2. Checking");  
                            
                                String accountChoice = stdIn.readLine();
                                if (!"1".equals(accountChoice) && !"2".equals(accountChoice)){
                                    System.out.println("incorrect input");
                                    continue;
                                }

                                out.println(accountChoice);
                                break;
                            }
                         
                            System.out.println("Enter recipient's ID: ");
                            String recipientId = stdIn.readLine();
                            out.println(recipientId);

                            System.out.println("Enter amount to be transferred: ");
                            String amount = stdIn.readLine();
                            out.println(amount);
                            
                            String transferResponse = in.readLine();
                            System.out.println(transferResponse);
                            break;

                        case "2":
                            String savingBalance = in.readLine();
                            String checkingBalance = in.readLine();  
                            System.out.println(savingBalance);
                            System.out.println(checkingBalance);                          
                            break;

                        case "3":
                            socket.close();
                            exit = true;
                            return;
                            
                        default:
                            String incorrect = in.readLine();
                            System.out.println(incorrect);
                            break;

                    }
                }
            }else {
                continue;
            } 
        }
    }



    public static void main(String[] args) throws Exception{
        String domain = args[0];
        int port = Integer.parseInt(args[1]);

        ATM atm = new ATM(domain,port);
        atm.connect();
        atm.run();
    }

    
}
