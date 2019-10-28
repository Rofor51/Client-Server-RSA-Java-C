package com.Server;

import com.RSA.GenerateKeyPair;
import com.RSA.RSAUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;

import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Client {

    public static final String BEGIN_CERT = "-----BEGIN PUBLIC KEY-----";
    public static final String END_CERT = "-----END PUBLIC KEY-----";



    public static void main(String[] args) throws NoSuchAlgorithmException {
        RSAUtil rsaUtil = new RSAUtil();

        GenerateKeyPair generateKeyPair = new GenerateKeyPair();
        String LINE_SEPARATOR = System.getProperty("line.separator");
        Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());
        StringBuilder sb = new StringBuilder();



        try {
            Socket client = new Socket("IP ADDRESS", PORT);

            PrintWriter out = new PrintWriter(client.getOutputStream(),true);

            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
            String PEM_FORMAT = BEGIN_CERT + LINE_SEPARATOR + encoder.encodeToString(generateKeyPair.getPublicKey().getEncoded()) + LINE_SEPARATOR + END_CERT;
            String PRIVATE_KEY = Base64.getEncoder().encodeToString(generateKeyPair.getPrivateKey().getEncoded());

            out.println(PEM_FORMAT);


            String check = "";

            while ((check = in.readLine()) != null) {
                sb.append(check);
            }


            System.out.println("Decrypting the cipher.....");

            String cipherText = sb.toString();
            System.out.println("Encrypted text:" + cipherText);

            System.out.println("Decrypted cipher: " + rsaUtil.decrypt(cipherText,PRIVATE_KEY));


        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }


}




