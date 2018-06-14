import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class WalletAddressValidator {

    // much borrowed from from https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java

    public static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";  // Everything except 0OIl
    private static final BigInteger ALPHABET_SIZE = BigInteger.valueOf(ALPHABET.length());
    public final static byte P2PK_ADDRESS_PREFIX = 0x12;

    private static MessageDigest md;

    public static boolean validateAddress(String walletAddress) {
        byte[] dataAndChecksum;



        // If illegal characters are encountered, the wallet address is invalid
        try {
            dataAndChecksum = base58ToRawBytes(walletAddress);
        }
        catch (IllegalArgumentException e) {
            return false;
        }
        // Java uses MessageDigest for SHA-256 hashing
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }


        // Base58Check strings are the payload (including version bytes), with the first 4 bytes of the double SHA-256
        // hash of the payload concatenated as a checksum.

        // So to validate, take the Base58Check string less the last 4 bytes, double SHA-256 hash it, and the first
        // 4 bytes of the result should match the last 4 bytes of the original Base58Check string.
        byte[] data = Arrays.copyOf(dataAndChecksum, dataAndChecksum.length - 4);
        byte[] doubleHash = md.digest(md.digest(data));
        byte[] checksum = Arrays.copyOfRange(dataAndChecksum, dataAndChecksum.length - 4, dataAndChecksum.length);

        // If the address prefix doesn't match SolarCoin's, reject
        if(dataAndChecksum[0] != P2PK_ADDRESS_PREFIX){
            return false;
        }

        if(Arrays.equals(Arrays.copyOf(doubleHash, 4), checksum)) {
            return true;
        }

        return false;
    }

    // Converts the given Base58Check string to a byte array, without checking or removing the trailing 4-byte checksum.
    private static byte[] base58ToRawBytes(String s) {
        // Parse base-58 string
        BigInteger num = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            num = num.multiply(ALPHABET_SIZE);
            int digit = ALPHABET.indexOf(s.charAt(i));
            if (digit == -1)
                throw new IllegalArgumentException("Invalid character for Base58Check");
            num = num.add(BigInteger.valueOf(digit));
        }

        // Strip possible leading zero due to mandatory sign bit
        byte[] b = num.toByteArray();
        if (b[0] == 0)
            b = Arrays.copyOfRange(b, 1, b.length);

        try {
            // Convert leading '1' characters to leading 0-value bytes
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            for (int i = 0; i < s.length() && s.charAt(i) == ALPHABET.charAt(0); i++)
                buf.write(0);
            buf.write(b);
            return buf.toByteArray();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}
