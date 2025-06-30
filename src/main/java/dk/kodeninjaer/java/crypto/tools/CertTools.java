package dk.kodeninjaer.java.crypto.tools;

import java.security.MessageDigest;
import java.util.Formatter;

public abstract class CertTools {

    public static String getFingerprint(byte[] encoded, String algorithm) {
    try {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hash = digest.digest(encoded);
        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format("%02X:", b);
        }
        String result = formatter.toString();
        formatter.close();
        return result.replaceAll(":$", "");  // remove trailing colon
    } catch (Exception e) {
        return "Error computing fingerprint: " + e.getMessage();
    }
}

}