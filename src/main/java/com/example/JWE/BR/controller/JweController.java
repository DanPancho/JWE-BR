package com.example.JWE.BR.controller;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.security.*;
import javax.crypto.Cipher;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;



@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/jwe")
public class JweController {
    private static final int KEY_SIZE = 32;
    private static final String KEYSTORE_FILE = "path/to/your/keystore.jks";
    private static final String KEYSTORE_PASSWORD = "your_keystore_password";
    private static final String ALIAS = "ifiPublicKey";
    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2txPHmrQi0XqbgYm4PJoV9c3uep6BUcraQHmeXPNqBr42ZPDiFrBcxd18Oj48x8Thnvo3rD89+X4swFzJCSnb/bJAiavaEt2ZxtI2CgqQW2HAuf0wZRlabMa00QACxIN1uhWmANJ3iY7E4tNSQHcbQXzmOCUULFeiPpoT3MdIBwG+OL04ZCaai+ZQgd301oZAQ9ysXbnx3bOI3LOr4zJPqOcnd9mC0mj+aBfszjB7saCh7zyEtAPghG3yn5gvA3PaD2eU4wtghzxTdMoq9tSBT2Hy4D2hzPGoi1e8mv5giBkpQahx/WDXfF1sMnkpW1EO0qUft2lhJsENXXq1Ac0fAgMBAAECggEAFVYZrDRnlq1JmQEueOIyyB+1FYUiH03S11uyGAkYr6fr7GQrMOufWqYMcCZJAEX/uq0a4QdvNyh8UHOCIkO8rKDagOjStZuAXyW1hHP1udfB+YR+iXk01bdgGNtTGf+irku1nXX5HdZlYp5uOOuoPPmPwT6LLejjruGKkok0iDd+q/K7aWDbitPs2+Swv+vwh4XZkkh30Nq4DUjmuFMb2U+zcKZk8ZYML3Yl95NcLgAL5dWQHr5wx26k6uw8Udnykp38FfybTnsreuhl28mW0frvwlRjvZ3fdBWwCz2bSOZGsjz+fMCZGQjRW9U+FTdBIeVmABttQ7sPzl4eTnEhoQKBgQDjkeXygMIa+wLru688WnlKuhht4jqTn+SvRiGIqgCTFJttivQtM1LkfVQEc6aeluXyA+o5HCDczOjEughEPurHGVPiydBWwNlxpmUDxV8Zh+mCFCj1H4lyduvwX7+GoqoFehDzOUsiyBV2Tch/dpJuAEZioZ4w64z2yEJ7yqjO8QKBgQDNiqQ7nEto/smmZDM/31EkQp6Z50WRQIbim+EieEYZabLDsYbucZW8lZsriKGj+of7FxAnbMVYUhSKfn+aYfRVOfCmE/CCRvN4ptgFJQR1gtKQt1bXgumC8RdSMNBpTrD3EQtrVjsHPxKGwiLcjBqprvX32Lx7bEHL0+j2zTJ9DwKBgCYxW01KzMjobcIQesV/TbH775OpjzktcZz1ATXFilkk8Tz+QCLB5VyRqCMjIcil/KuUep/hF6bXAQ3bRv3lLVQC7TA3vK6CqTvIuFVcr6xCQi9hoMoa49+BE/IAr80xyaUnqmaXrAOHXwq+3TJ/PO4XP7jX9QuyzLKyQ24xQgmRAoGABKHcQ6+pD2u2lbZqZUUeKggKVQOeUMC4iYDj2QgG5Gm6aqikltkee8qPXbLNmcl6qREC/zB3Xh8zcU+ahpswi38rykJmyDjbIdv4wFzuNcvF/Rb0sRS1OItAcEzDVaw9VsQeksO1vtsQCtNzP680pqBX0McksE9nSDW1aWKEgccCgYEAl4BqWGYpycOXOSNpZbkoMHV9hG9FWfZ3hHn/DDutMAkrFWgIhdBQnfqRYtctSb3lG3ch2VL26sb3xVbOXChvUbsvdxn6M780jvJpFg/sjBvvef9f2AWNLOxktbuWyHM3mVgLTlniw5H/y6rqgC+3Z4UexsBKjU8XYJiajkpTQ5Y=-----END PRIVATE KEY-----";



    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtrcTx5q0ItF6m4GJuDyaFfXN7nqegVHK2kB5nlzzaga+NmTw4hawXMXdfDo+PMfE4Z76N6w/Pfl+LMBcyQkp2/2yQImr2hLdmcbSNgoKkFthwLn9MGUZWmzGtNEAAsSDdboVpgDSd4mOxOLTUkB3G0F85jglFCxXoj6aE9zHSAcBvji9OGQmmovmUIHd9NaGQEPcrF258d2ziNyzq+MyT6jnJ3fZgtJo/mgX7M4we7Ggoe88hLQD4IRt8p+YLwNz2g9nlOMLYIc8U3TKKvbUgU9h8uA9oczxqItXvJr+YIgZKUGocf1g13xdbDJ5KVtRDtKlH7dpYSbBDV16tQHNHwIDAQAB-----END PUBLIC KEY-----";

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody String json) throws Exception {
        boolean  test = false;
        PublicKey serverPublicKey;
        if (test){
            KeyStore keystore = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
                keystore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }
            Certificate cert = (Certificate) keystore.getCertificate(ALIAS);
            serverPublicKey = cert.getPublicKey();
        }else {
            serverPublicKey = getPublicKeyFromString(PUBLIC_KEY);
        }

        byte[] secretKey = generateSecretKey(KEY_SIZE);
        PrivateKey serverPrivateKey = getPrivateKeyFromString(PRIVATE_KEY);

        String encryptedJson = encryptJson(json, secretKey);
        System.out.println("Encrypted JSON: " + encryptedJson);
        String encryptedSecretKey = encryptSecretKey(secretKey, serverPublicKey);
        System.out.println("Encrypted Secret Key: " + encryptedSecretKey);


        byte[] decryptedSecretKey = decryptSecretKey(encryptedSecretKey, serverPrivateKey);
        System.out.println("Decrypted SECRET: " + decryptedSecretKey);
        String decryptedMessage = decryptWithJwe(encryptedJson, decryptedSecretKey);
        System.out.println("Decrypted Message: " + decryptedMessage);

        return "{"
        + "\"encryptedJson\":\"" + encryptedJson + "\","
        + "\"encryptedSecretKey\":\"" + encryptedSecretKey + "\""
        + "}";

    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestHeader("x-key") String encryptedSecretKey, @RequestBody String encryptedJson) throws Exception {

        PrivateKey serverPrivateKey = getPrivateKeyFromString(PRIVATE_KEY);
      
        byte[] decryptedSecretKey = decryptSecretKey(encryptedSecretKey, serverPrivateKey);
        System.out.println("Decrypted SECRET: " + decryptedSecretKey);
        String decryptedMessage = decryptWithJwe(encryptedJson, decryptedSecretKey);
        System.out.println("Decrypted Message: " + decryptedMessage);

        return decryptedMessage;
    }


    private static byte[] generateSecretKey(int keySize) throws Exception {
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] randomBytes = new byte[keySize];
        secureRandom.nextBytes(randomBytes);
        System.out.println("SECRET KEY: " + randomBytes);
        return randomBytes;
    }

    private static String encryptJson(String json, byte[] secretKey) throws Exception {
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
        Payload payload = new Payload(json);
        JWEObject jweObject = new JWEObject(header, payload);
        DirectEncrypter encrypter = new DirectEncrypter(secretKey);
        jweObject.encrypt(encrypter);
        return jweObject.serialize();
    }

    private static String encryptSecretKey(byte[] secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(secretKey));
    }

   

    private static byte[] decryptSecretKey(String encryptedSecretKey, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decodedKey = Base64.getDecoder().decode(encryptedSecretKey);
            return cipher.doFinal(decodedKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decryptWithJwe(String JsonEncrypt, byte[] secretKey) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(JsonEncrypt);
        DirectDecrypter decrypter = new DirectDecrypter(secretKey);
        jweObject.decrypt(decrypter);
        return jweObject.getPayload().toString();
    }
     

    // PRIMERO CREAR EL KEYSTORE PENDEINTE 

    private static PublicKey getPublicKeyFromString(String key) throws Exception {
        String publicKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----", "")
                                 .replace("-----END PUBLIC KEY-----", "")
                                 .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey getPrivateKeyFromString(String key) throws Exception {
        String privateKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----", "")
                                  .replace("-----END PRIVATE KEY-----", "")
                                  .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }
}
