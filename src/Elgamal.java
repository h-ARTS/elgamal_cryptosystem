import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

public class Elgamal {
    public static final BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    public static final BigInteger GENERATOR = BigInteger.TWO;
    public static BigInteger a;
    public static BigInteger b;
    public static BigInteger g_b;

    public static void main(String[] args) throws IOException {
        /*
        * Uncomment codes down below for encryption/decryption of text.
        * */
//        encryptText("src/text.txt");
        System.out.println(decryptCipherText("src/chiffre.txt", "src/sk.txt"));
//        BigInteger THREE = new BigInteger("3");
//        BigInteger M = new BigInteger("38");
//        System.out.println(THREE.pow(THREE.intValue()).modInverse(M));
//        System.out.println((BigInteger.valueOf(6).multiply(fastExponentiation(BigInteger.valueOf(4), BigInteger.valueOf(3), BigInteger.valueOf(13)))).mod(BigInteger.valueOf(13)));
    }

    public static void generateKeyPairs() throws IOException {
        setB(nextRandom());
        setA(nextRandom());
        setG_b(GENERATOR.modPow(b, N));
        saveKeyPairs();
    }

    public static BigInteger nextRandom() {
        /*
        * Randomly generate a BigInteger with bit length of 2048.
        * When less than 0 then correct it.
        * */
        BigInteger max = N.subtract(BigInteger.ONE);
        BigInteger min = BigInteger.ZERO;
        Random randNum = new Random();
        int len = N.bitLength();
        BigInteger randB = new BigInteger(len, randNum);
        return randB.compareTo(min) < 0 ? randB.add(min) : randB.mod(max);
    }

    /*
     * The fast exponentiation algorithm reused from assignment 1
     */
    private static BigInteger fastExponentiation(BigInteger k, BigInteger e, BigInteger n) {
        BigInteger h = BigInteger.ONE;

        String binaryString = e.toString(2);
        // Deduct 1 otherwise out of range
        int l = Arrays.asList(binaryString.split("")).size()-1;

        List<String> binaries = Arrays.asList(binaryString.split(""));

        while (l >= 0) {
            if (binaries.get(l).equals("1"))
                h = h.multiply(k).mod(n);

            k = k.pow(2).mod(n);
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

    /*
    * Save key pairs in their respective files.
    * */
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

    /*
    * Transform into cipher text by using the elgamal encryption formula from slide 2.27
    * */
    public static void encryptText(String pathname) throws IOException {
        generateKeyPairs();
        List<Character> chars = getListOfCharCodesFromFile(pathname);
        List<String> encryptions = new ArrayList<>();
        chars.stream()
                .map(character -> BigInteger.valueOf((long)character))
                .forEach((ascii) -> {
            BigInteger y_1 = GENERATOR.modPow(a, N);
            BigInteger y_2 = (g_b.modPow(a, N).multiply(ascii).mod(N)).mod(N);
            encryptions.add("(" + y_1 + "," + y_2 + ");");
        });

        // For eliminating the last semicolon.
        StringBuffer cipherBuffer = new StringBuffer(encryptions.stream()
                .map(String::toString)
                .collect(Collectors.joining()));
        cipherBuffer.deleteCharAt(cipherBuffer.length()-1);

        String cipher = cipherBuffer.toString();

        saveTextInFile(cipher, "output/cipher.txt");
    }

    /*
    * Decrypt cipher text and save in a file.
    * */
    public static String decryptCipherText(String pathNameToCipher, String pathNameToPrivateKey) throws IOException {
        String cipherText = loadTextFile(pathNameToCipher);
        String privateKey = loadTextFile(pathNameToPrivateKey);

        // Split by semicolon to loop over the encrypted cipher.
        List<String> keyPairs = Arrays.asList(cipherText.split("[;]", 0));
        List<BigInteger> asciiCodes = new ArrayList<>();
        keyPairs.forEach(keyPair -> {
            asciiCodes.add(decryptAscii(keyPair, privateKey));
        });

        // The juicy part were you press the ascii codes into real characters and store it as a string
        String plainText = asciiCodes.stream()
                .map(BigInteger::intValue)
                .map(Character::toString)
                .collect(Collectors.joining());

        saveTextInFile(plainText, "src/text-d.txt");

        return plainText;
    }

    /*
    * Transform into ascii code by using the elgamal decryption formula from slide 2.27
    * */
    private static BigInteger decryptAscii(String keyPair, String privateKey) {
        // Replace parens with empty space
        List<String> keyPairString = List.of(keyPair.replaceAll("[()]", "").split(","));
        BigInteger y_1 = new BigInteger(keyPairString.get(0));
        BigInteger y_2 = new BigInteger(keyPairString.get(1));

        // Decrypt y_1 and y_2 with fast exponentiation.
        BigInteger y_1_power_b = fastExponentiation(y_1, new BigInteger(privateKey), N);
        BigInteger y_1_inverse = y_1_power_b.modInverse(N);
        BigInteger output = y_2.multiply(y_1_inverse).mod(N);

        return output;
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

    /* Setters */
    public static void setB(BigInteger b) {
        Elgamal.b = b;
    }

    public static void setA(BigInteger a) {
        Elgamal.a = a;
    }

    public static void setG_b(BigInteger g_b) {
        Elgamal.g_b = g_b;
    }
}
