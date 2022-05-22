import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public class Elgamal {
    public static final BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    public static BigInteger a;
    public static BigInteger b;
    public static BigInteger g_b;
    public static final BigInteger g = BigInteger.TWO;

    public static void main(String[] args) throws IOException {
        generateKeyPairs();
    }

    public static void generateKeyPairs() throws IOException {
        b = nextRandom();
        a = nextRandom();
        g_b = g.modPow(b, n);
        saveKeyPairs();
    }

    public static BigInteger nextRandom() {
        /*
        * Randomly generate a BigInteger with bit length of 2048.
        * When less than 0 then correct it.
        * */
        BigInteger max = n.subtract(BigInteger.ONE);
        BigInteger min = BigInteger.ZERO;
        Random randNum = new Random();
        int len = n.bitLength();
        BigInteger randB = new BigInteger(len, randNum);
        return randB.compareTo(min) < 0 ? randB.add(min) : randB.mod(max);
    }
    /*
    * Extended euclidean algorithm reused from assignment 1
    * */
    public static BigInteger extendedEuclidean(BigInteger phiOfN, BigInteger chosenE) {
        /*
         * Get phi of n and set this to equals an
         * e will be equals b
         * init x_0 = 1, y_0 = 0, x_1 = 0, y_1 = 1
         */
        BigInteger a = phiOfN;
        BigInteger b = chosenE;
        BigInteger q; // div
        BigInteger r; // mod
        BigInteger temp; // For not skipping values...
        BigInteger x_0 = BigInteger.ONE,
                y_0 = BigInteger.ZERO,
                x_1 = BigInteger.ZERO,
                y_1 = BigInteger.ONE;

        while (!b.equals(BigInteger.ZERO)) {
            q = a.divide(b);
            r = a.mod(b);

            a = b;
            b = r;

            /*
             * The temp is for storing the x_1 value temporary,
             * so you do not use the overwritten x_1 as seen below
             */
            temp = x_1;
            x_1 = x_0.subtract(q.multiply(x_1));
            x_0 = temp;

            // Same goes to y_1
            temp = y_1;
            y_1 = y_0.subtract(q.multiply(y_1));
            y_0 = temp;
        }

        // If y_0 is positive ? e = y_0 or e = y_0 + phi(n) if y_0 negative
        if (y_0.intValue() < 0) {
//            setD(y_0.add(phiOfN));
        } else {
//            setD(y_0);
        }

        // According to 1.27: x_0 * a + b * y_0
        return x_0.multiply(phiOfN).add(y_0.multiply(chosenE));
    }


    /*
     * The fast exponentiation algorithm reused from assignment 1
     */
    private static BigInteger fastExponentiation(BigInteger _k, BigInteger _e, BigInteger _n) {
        BigInteger h = BigInteger.ONE;
        BigInteger k = _k;

        String binaryString = _e.toString(2);
        // Deduct 1 otherwise out of range
        int l = Arrays.asList(binaryString.split("")).size()-1;

        List<String> binaries = Arrays.asList(binaryString.split(""));

        while (l >= 0) {
            if (binaries.get(l).equals("1"))
                h = h.multiply(k).mod(_n);

            k = k.pow(2).mod(_n);
            l--;
        }

        return h;
    }

    /*
    * List of ascii character codes method from assignment 1
    * */
    private static List<Character> getListOfCharCodesFromFile(String pathname) throws IOException {
        // Load a file
        FileReader file = new FileReader(pathname);
        BufferedReader reader = new BufferedReader(file);
        String plainText = reader.readLine();
        reader.close();

        // convert every single character string representation into character type
        List<String> charsString = Arrays.asList(plainText.split("", 0));

        return charsString.stream().map(c -> c.charAt(0)).toList();
    }


    private static void saveKeyPairs() throws IOException {
        FileWriter publicKeyFile = new FileWriter("output/pk.txt");
        FileWriter privateKeyFile = new FileWriter("output/sk.txt");

        BufferedWriter publicKeyWriter = new BufferedWriter(publicKeyFile);
        BufferedWriter privateKeyWriter = new BufferedWriter(privateKeyFile);

        publicKeyWriter.write(g_b.toString());
        privateKeyWriter.write(b.toString());

        publicKeyWriter.close();
        privateKeyWriter.close();
    }

    public static String decryptCipherText(String pathNameToCipher, String pathNameToPrivateKey) throws IOException {
        String cipherText = loadTextFile(pathNameToCipher);
        String privateKeyText = loadTextFile(pathNameToPrivateKey);

        List<String> keyPair = Arrays.asList(privateKeyText.split("[,]", 0));
        // Replace parens with empty space
        keyPair.replaceAll(s -> s.replaceAll("[()]", ""));
        BigInteger _n = new BigInteger(keyPair.get(0)); // n
        BigInteger _d = new BigInteger(keyPair.get(1)); // d

        // split by comma, decipher with fast exponentiation and store in a list
        List<String> listCiphers = Arrays.stream(cipherText.split("[,]")).toList();
        List<BigInteger> asciiCodes = listCiphers.stream()
                .map(BigInteger::new)
                .map(cipherBigInt -> fastExponentiation(cipherBigInt, _d, _n))
                .toList();

        // The juicy part were you press the ascii codes into real characters and store it as a string
        String plainText = asciiCodes.stream()
                .map(BigInteger::intValue)
                .map(Character::toString)
                .collect(Collectors.joining());

        saveTextInFile(plainText, "text-d.txt");

        return plainText;
    }

    private static void saveTextInFile(String rawText, String filename) throws IOException {
        FileWriter cipherTextFile = new FileWriter(filename);
        BufferedWriter cipherWriter = new BufferedWriter(cipherTextFile);

        cipherWriter.write(rawText);

        cipherWriter.close();
    }

    private static String loadTextFile(String pathname) throws IOException {
        FileReader textFile = new FileReader(pathname);
        BufferedReader reader = new BufferedReader(textFile);

        return reader.readLine();
    }

    /* Getters and setters */
    public static BigInteger getB() {
        return b;
    }

    public static void setB(BigInteger b) {
        Elgamal.b = b;
    }
}
