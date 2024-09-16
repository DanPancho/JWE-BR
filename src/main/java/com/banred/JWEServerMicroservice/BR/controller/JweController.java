package com.banred.JWEServerMicroservice.BR.controller;

import com.banred.JWEServerMicroservice.BR.data.Request;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/jwe")
public class JweController {
    @Value("${microservice.parameters.JWE_ENCRIPTION_KEY_SIZE}")
    private int KEY_SIZE;
    @Value("${microservice.parameters.SECRET_KEY_CERT_PATH}")
    private String PUBLIC_KEY_PATH_FILE;
    @Value("${microservice.parameters.PRIVATE_KEY_CERT_PATH}")
    private String PRIVATE_KEY;
    @Value("${microservice.parameters.SECRET_KEY_ENABLE_ENCRIPTION}")
    private Boolean ENCRYPT_SECRET;

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody Request json) throws Exception {

        String jsonReq = json.getJsonReq();
        String pathFile = json.getFilePath();

        byte[] secretKey = generateSecretKey(KEY_SIZE);
        String secreteClaro = Base64.getEncoder().encodeToString(secretKey);

        if (ENCRYPT_SECRET) {
            PublicKey serverPublicKey = getPublicKey(PUBLIC_KEY_PATH_FILE + pathFile);
            String encryptedSecretKey = encryptSecretKey(secretKey, serverPublicKey);
            System.out.println("SECRETO ENCRIPTADO:  " + encryptedSecretKey);
            String encryptedJson = encryptJson(jsonReq, secretKey);
            System.out.println("Encrypted JSON: " + encryptedJson);
            return "{"
                    + "\"encryptedJson\":\"" + encryptedJson + "\","
                    + "\"encryptedSecretKey\":\"" + encryptedSecretKey + "\""
                    + "}";
        } else {
            String encryptedJson = encryptJson(jsonReq, secretKey);
            System.out.println("Encrypted JSON: " + encryptedJson);
            return "{"
                    + "\"encryptedJson\":\"" + encryptedJson + "\","
                    + "\"encryptedSecretKey\":\"" + secreteClaro + "\""
                    + "}";
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestHeader("x-key") String encryptedSecretKey, @RequestBody String encryptedJson)
            throws Exception {

        PrivateKey serverPrivateKey = getPrivateKeyFromString(PRIVATE_KEY);

        if (ENCRYPT_SECRET) {
            String decryptedSecretKey = decryptSecretKey(encryptedSecretKey, serverPrivateKey);
            System.out.println("SECRETO DESENCRIPTADO:  " + decryptedSecretKey);
            byte[] decryptedSecretKeyByte = Base64.getDecoder().decode(decryptedSecretKey);
            String decryptedMessage = decryptWithJwe(encryptedJson, decryptedSecretKeyByte);
            System.out.println("Decrypted Message: " + decryptedMessage);
            return decryptedMessage;
        } else {
            byte[] decryptedSecretKey = Base64.getDecoder().decode(encryptedSecretKey);
            System.out.println("SECRET BASE 64: " + decryptedSecretKey);
            String decryptedMessage = decryptWithJwe(encryptedJson, decryptedSecretKey);
            System.out.println("Decrypted Message: " + decryptedMessage);
            return decryptedMessage;      
        }

    }

    private static byte[] generateSecretKey(int keySize) throws Exception {
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] randomBytes = new byte[keySize];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    private static String encryptJson(String json, byte[] secretKey) throws Exception {
        SecretKey key = new SecretKeySpec(secretKey, "AES");
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
        Payload payload = new Payload(json);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new DirectEncrypter(key));
        return jweObject.serialize();
    }

    private static String encryptSecretKey(byte[] secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(secretKey));
    }

    private static String decryptSecretKey(String encryptedSecretKey, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedSecretKey)));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decryptWithJwe(String JsonEncrypt, byte[] secretKey) throws ParseException, JOSEException {
        SecretKey key = new SecretKeySpec(secretKey, "AES"); 
        JWEObject jweObject = JWEObject.parse(JsonEncrypt);
        jweObject.decrypt(new DirectDecrypter(key));
        return jweObject.getPayload().toString();
    }

    private static PublicKey getPublicKey(String path) {
        try {

            String publicKeyPEM = new String(Files.readAllBytes(Paths.get(path)))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "")
                    .replaceAll(System.lineSeparator(), "");
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e);
            return null;
        }
    }

    private static PrivateKey getPrivateKeyFromString(String path) throws Exception {
        String privateKeyPEM = new String(Files.readAllBytes(Paths.get(path)))
                            .replace("-----BEGIN PRIVATE KEY-----", "")
                            .replaceAll(System.lineSeparator(), "")
                            .replace("-----END PRIVATE KEY-----", "")
                            .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }
}
