import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Bank {
    private int port;
    private ServerSocket serverSocket;
    private Map<String, String> idToPassword = new HashMap<>();
    private Map<String, double[]> idToBalanceMap = new HashMap<>();

    public Bank(int port) {
        this.port = port;
        loadPasswordFile();
        loadBalanceFile();
    }

    private byte[] decryptWithPrivateKey(byte[] ciphertext, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    private String decryptWithSymmetricKey(byte[] ciphertext, SecretKey symmetricKey) throws Exception{
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    private PrivateKey loadPrivateKey() throws Exception{
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get("privateKey"));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public void start() throws Exception {
        serverSocket = new ServerSocket(port);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            handleClient(clientSocket);
        }
    }

    private void transferAmount(String senderId, String recipientId, int accountType, double amount) {
        double[] senderBalances = idToBalanceMap.get(senderId);
        double[] recipientBalances = idToBalanceMap.get(recipientId);

        senderBalances[accountType] -= amount;
        recipientBalances[accountType] += amount;
    }

    private void updateBalanceFile() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("balance"))) {
            for (Map.Entry<String, double[]> entry : idToBalanceMap.entrySet()) {
                writer.write(entry.getKey() + " " + entry.getValue()[0] + " " + entry.getValue()[1] + "\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleClient(Socket socket) throws Exception {
        try(
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);)
        {
            String id = null;
            // Authentication loop
            while (true) {
                PrivateKey bankPrivateKey = loadPrivateKey();
                String receivedEncryptedKey = in.readLine();
                String receivedEncryptedCredentials = in.readLine();

                byte[] decryptedSymmetricKeyBytes = decryptWithPrivateKey(Base64.getDecoder().decode(receivedEncryptedKey), bankPrivateKey);
                SecretKey symmetricKey = new SecretKeySpec(decryptedSymmetricKeyBytes, 0, decryptedSymmetricKeyBytes.length, "AES");
                String credentials = decryptWithSymmetricKey(Base64.getDecoder().decode(receivedEncryptedCredentials), symmetricKey);

                String[] parts = credentials.split(":");
                id = parts[0];
                String password = parts[1];
                System.out.println(id);
                System.out.println(password);

                //id = in.readLine();
                //String password = in.readLine();

                if (idToPassword.containsKey(id) && idToPassword.get(id).equals(password)) {
                    out.println("ID and password are correct");
                    break;  
                } else {
                    out.println("ID or password is incorrect");
                }      
            }

            // Handling actions
            while (true) {
                String action = in.readLine();

                switch (action) {
                    case "1":
                        int accountType = Integer.parseInt(in.readLine()) - 1;
                        String recipientId = in.readLine();
                        double amount = Double.parseDouble(in.readLine());

                        if (!idToBalanceMap.containsKey(recipientId)) {
                            out.println("The recipient's ID does not exist");
                        } else if (idToBalanceMap.get(id)[accountType] < amount) {
                            out.println("Your account does not have enough funds");
                        } else {
                            transferAmount(id, recipientId, accountType, amount);
                            updateBalanceFile();
                            out.println("Your transaction is successful");
                        }
                        break;

                        case "2":
                        out.println("Your savings account balance: " + idToBalanceMap.get(id)[0]);
                        out.println("Your checking account balance: " + idToBalanceMap.get(id)[1]);
                        break;

                    case "3":
                        in.close();
                        out.close();
                        socket.close();
                        return;
                    
                    default:
                        out.println("incorrect input");
                        break;
                }
            }
            
        }   
    }

    private void loadPasswordFile() {
        try (BufferedReader reader = new BufferedReader(new FileReader("password"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length == 2) {
                    idToPassword.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void loadBalanceFile() {
        try (BufferedReader reader = new BufferedReader(new FileReader("balance"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length == 3) {
                    idToBalanceMap.put(parts[0], new double[]{Double.parseDouble(parts[1]), Double.parseDouble(parts[2])});
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        Bank bank = new Bank(port);
        bank.start();
    }
}
