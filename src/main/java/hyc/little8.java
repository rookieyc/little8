package hyc;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;

public class little8 {

//    static SecureRandom random;

    public static void main (String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        try {
            experimentOne();
            experimentTwo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void experimentOne() {
        Logger logger = Logger.getLogger("One");

        Random random = new Random();
        byte[] S = new byte[32], D = new byte[32], M = new byte[32];

        long t1 = System.currentTimeMillis();

        random.nextBytes(S);
//        logger.info("S: " + Hex.toHexString(S));
        random.nextBytes(D);
        random.nextBytes(M);

        long t2 = System.currentTimeMillis();
        logger.warning("time interval: " + (t2 - t1));
    }

    private static void experimentTwo() throws Exception {
        Logger logger = Logger.getLogger("Two");

        Random random = new Random();
        byte[] S = new byte[32], D = new byte[32], M = new byte[32], r = new byte[32];
        byte[] m1 = new byte[32], m3 = new byte[32];

        MessageDigest messageDigest = null;
        Cipher iesCipher = null;

        messageDigest = MessageDigest.getInstance("SHA-256");
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
        iesCipher = Cipher.getInstance("ECIESwithAES-CBC");
        iesCipher.init(Cipher.ENCRYPT_MODE, ecKeyPair.getPublic());

        long t1 = System.currentTimeMillis();

        random.nextBytes(S);
        random.nextBytes(D);
        random.nextBytes(M);
        random.nextBytes(r);

        // r = H(r)
        r = messageDigest.digest(r);

        // S xor r
        int i = 0;
        for (byte s : S) {
            m1[i] = (byte) (s ^ r[i++]);
        }

        // ECIES
        byte[] m2 = new byte[M.length + r.length];
        System.arraycopy(M, 0, m2, 0, M.length);
        System.arraycopy(r, 0, m2, M.length, r.length);
        m3 = iesCipher.doFinal(m2);
//        logger.info("m3: " + Hex.toHexString(m3));

        long t2 = System.currentTimeMillis();
        logger.warning("time interval: " + (t2 - t1));
    }
}