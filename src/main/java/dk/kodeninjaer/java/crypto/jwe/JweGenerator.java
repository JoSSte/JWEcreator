package dk.kodeninjaer.crypto.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Map;

public class JweGenerator {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Load configuration
        Yaml yaml = new Yaml();
        InputStream configStream = JweGenerator.class.getClassLoader().getResourceAsStream("application.yaml");
        Map<String, Map<String, String>> config = yaml.load(configStream);
        Map<String, String> keystoreConfig = config.get("keystore");

        String keystorePath = keystoreConfig.get("path");
        String keystorePassword = keystoreConfig.get("password");
        String keyAlias = keystoreConfig.get("alias");

        // Load public key from keystore
        InputStream keystoreStream = JweGenerator.class.getClassLoader().getResourceAsStream(keystorePath);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(keystoreStream, keystorePassword.toCharArray());
        Certificate cert = ks.getCertificate(keyAlias);
        PublicKey publicKey = cert.getPublicKey();

        // Create JWE header
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("text/plain")
                .customParam("example", "header-as-aad")
                .build();

        // Payload to encrypt
        Payload payload = new Payload("This is a secret message");

        // JWE Object
        JWEObject jweObject = new JWEObject(header, payload);

        // Encrypter using RSA-OAEP-256
        RSAEncrypter encrypter = new RSAEncrypter(publicKey);

        // Perform encryption (header used automatically as AAD)
        jweObject.encrypt(encrypter);

        // Output the compact JWE
        String jweString = jweObject.serialize();
        System.out.println("Generated JWE:");
        System.out.println(jweString);

        // Optional: Show AAD (header in Base64URL)
        Base64URL aad = header.toBase64URL();
        System.out.println("AAD (Base64URL Header): " + aad.toString());
    }
}
