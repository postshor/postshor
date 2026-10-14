import java.security.*;
import javax.crypto.*;

public class Crypto {
    void run() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Signature sig = Signature.getInstance("SHA256withECDSA");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        MessageDigest md = MessageDigest.getInstance("MD5");
        KeyPairGenerator pq = KeyPairGenerator.getInstance("ML-KEM-768");
    }
}
