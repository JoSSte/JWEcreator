package dk.kodeninjaer.java.crypto.jwe;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;

public class JweDecryptor {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Load configuration from application.yaml
        Yaml yaml = new Yaml();
        InputStream configStream = JweDecryptor.class.getClassLoader().getResourceAsStream("application.yaml");
        Map<String, Map<String, String>> config = yaml.load(configStream);
        Map<String, String> keystoreConfig = config.get("keystore");

        String keystorePath = keystoreConfig.get("path");
        String keystorePassword = keystoreConfig.get("password");
        String keyAlias = keystoreConfig.get("alias");

        // Load private key from keystore
        InputStream keystoreStream = JweDecryptor.class.getClassLoader().getResourceAsStream(keystorePath);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(keystoreStream, keystorePassword.toCharArray());
        Key key = ks.getKey(keyAlias, keystorePassword.toCharArray());

        if (!(key instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("The loaded key is not an RSA private key.");
        }

        RSAPrivateKey privateKey = (RSAPrivateKey) key;

        // TODO: get from parameter
        // Replace this with the actual JWE string you want to decrypt
        String jweString = "<Paste_Your_JWE_Here>";

        // Parse the JWE
        JWEObject jweObject = JWEObject.parse(jweString);

        // Decrypt
        RSADecrypter decrypter = new RSADecrypter(privateKey);
        jweObject.decrypt(decrypter);

        // Get the payload
        String decryptedPayload = jweObject.getPayload().toString();
        System.out.println("Decrypted Payload: " + decryptedPayload);
    }
}
