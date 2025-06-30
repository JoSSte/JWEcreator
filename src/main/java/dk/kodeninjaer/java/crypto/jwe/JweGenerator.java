package dk.kodeninjaer.java.crypto.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import dk.kodeninjaer.java.crypto.tools.CertTools;

public class JweGenerator {
    static RSAPublicKey rsaPublicKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // TODO: move to CertTools
    
    /**
     * function to load keys from keystore as defined in application.yaml
     */
    public static void loadConfig() {
        // Load configuration
        Yaml yaml = new Yaml();
        InputStream configStream = JweGenerator.class.getClassLoader().getResourceAsStream("application.yaml");
        Map<String, Map<String, String>> config = yaml.load(configStream);
        Map<String, String> keystoreConfig = config.get("keystore");

        String keystorePath = keystoreConfig.get("path");
        String keystorePassword = keystoreConfig.get("password");
        String keyAlias = keystoreConfig.get("alias");

        // Load public key from keystore
        try {
            InputStream keystoreStream = JweGenerator.class.getClassLoader().getResourceAsStream(keystorePath);
            KeyStore ks = KeyStore.getInstance("PKCS12");
        
            ks.load(keystoreStream, keystorePassword.toCharArray());

            Certificate cert = ks.getCertificate(keyAlias);
            PublicKey publicKey = cert.getPublicKey();

            if (!(publicKey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("The loaded public key is not an RSA public key.");
            }

            rsaPublicKey = (RSAPublicKey) publicKey;

            //Dump Certificate information for debug purposes
            X509Certificate x509Certificate = (X509Certificate)  cert;
            byte[] encodedCert = cert.getEncoded();
            
            // Dump Certificate informaiton
            System.out.println("** Information about loaded Certificate: **");
            System.out.println("Name:\t\t\t" + x509Certificate.getSubjectX500Principal().getName());
            System.out.println("Serial:\t\t\t" + x509Certificate.getSerialNumber());
            System.out.println("SHA-1 fingerprint:\t" + CertTools.getFingerprint(encodedCert, "SHA-1"));
            System.out.println("SHA-256 fingerprint:\t" + CertTools.getFingerprint(encodedCert, "SHA-256"));
            System.out.println("\n");

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        loadConfig();
        // Create JWE header
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("text/plain")
                // .customParam("example", "header-as-aad")
                .build();

        // Payload to encrypt
        Payload payload = new Payload("{\"message\" : \"This is a very secret message\"}");

        // JWE Object
        JWEObject jweObject = new JWEObject(header, payload);

        // Encrypter using RSA-OAEP-256
        RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);

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
