//package pkiTest;
//
//import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetException;
//import main.de.htw.berlin.s0551733.sharknetpki.impl.SharknetPKI;
//import org.bouncycastle.operator.OperatorCreationException;
//
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.IOException;
//import java.security.*;
//import java.security.cert.CertificateException;
//import java.security.cert.X509Certificate;
//import java.util.HashSet;
//
//public class Main {
//
//    private static final String PATH = "/Users/pascaldettmers/Documents/Project/Bachelor/NeueBASchwotzerApp/sharknetpki/src/main/resources/data/keystore.ks";
//
//    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException, SharkNetException {
//        SharknetPKI pki = SharknetPKI.init("pw".toCharArray());
//        try {
//            System.out.println("Public Key: " + pki.getMyOwnPublicKey().toString());
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//
//        PublicKey publicKey = pki.getMyOwnPublicKey();
//
//        SecureRandom secRandom = new SecureRandom();
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//        keyGen.initialize(2048, secRandom);
//        KeyPair keypair = keyGen.generateKeyPair();
//
//        SecureRandom secRandomB = new SecureRandom();
//        KeyPairGenerator keyGenB = KeyPairGenerator.getInstance("RSA");
//        keyGen.initialize(2048, secRandom);
//        KeyPair keypairB = keyGen.generateKeyPair();
//
//        X509Certificate x509Certificate = null;
//        try {
//            x509Certificate = pki.generateCertificate(keypair.getPublic(), pki.getPrivateKey(), "localhost", "thirparty");
//        } catch (UnrecoverableKeyException | OperatorCreationException | KeyStoreException e) {
//            e.printStackTrace();
//        }
//        System.out.println("Certificate: " + x509Certificate.toString());
//        try {
//            x509Certificate.verify(pki.getMyOwnPublicKey());
//        } catch (Exception e) {
//            if (e instanceof InvalidKeyException) {
//                System.out.println("wrong Key");
//            }
//            if (e instanceof SignatureException) {
//                System.out.println("Signature error");
//            }
//            e.printStackTrace();
//        }
//
//        pki.persistKeyStore(new FileOutputStream(PATH));
//        pki.loadKeyStore(new FileInputStream(PATH));
//    }
//
//}
