package pkiTest;

import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetExcption;
import main.de.htw.berlin.s0551733.sharknetpki.impl.SharknetPKI;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Main {

    private static final String PATH = "/Users/pascaldettmers/Documents/Project/Bachelor/NeueBASchwotzerApp/sharknetpki/src/main/resources/data/keystore.ks";

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException, SharkNetExcption {
        SharknetPKI pki = new SharknetPKI("pw".toCharArray());
        try {
            System.out.println("Public Key: " + pki.getPublicKey().toString());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        PublicKey publicKey = pki.getPublicKey();

        SecureRandom secRandom = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secRandom);
        KeyPair keypair = keyGen.generateKeyPair();

        SecureRandom secRandomB = new SecureRandom();
        KeyPairGenerator keyGenB = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secRandom);
        KeyPair keypairB = keyGen.generateKeyPair();

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = pki.generateCertificateWithCertBuilder(keypair.getPublic(), pki.getPrivateKey(), "localhost", "thirparty");
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
        System.out.println("Certificate: " + x509Certificate.toString());
        try {
            x509Certificate.verify(pki.getPublicKey());
        } catch (Exception e) {
            if (e instanceof InvalidKeyException) {
                System.out.println("wrong Key");
            }
            if (e instanceof SignatureException) {
                System.out.println("Signature error");
            }
            e.printStackTrace();
        }

        pki.persistKeyStore(new FileOutputStream(PATH));
        pki.loadKeyStore(new FileInputStream(PATH));
    }

    // BC
//    private static KeyPair createKeyPairWithBC() throws NoSuchAlgorithmException, InvalidKeySpecException {
//        SecureRandom sr = new SecureRandom();
//        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
//        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3), sr, 1024, 80));
//        AsymmetricCipherKeyPair keypair = gen.generateKeyPair();
//        RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic();
//        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair.getPrivate();
//        // used to get proper encoding for the certificate
//        RSAPublicKeyStructure pkStruct = new RSAPublicKeyStructure(publicKey.getModulus(), publicKey.getExponent());
//        // JCE format needed for the certificate - because getEncoded() is necessary…
//        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(
//                new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
//        // and this one for the KeyStore
//        PrivateKey privKey = KeyFactory.getInstance("RSA").generatePrivate(
//                new RSAPrivateCrtKeySpec(publicKey.getModulus(), publicKey.getExponent(),
//                        privateKey.getExponent(), privateKey.getP(), privateKey.getQ(),
//                        privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()));
//        return new KeyPair(pubKey,privKey);
//    }

//    // JCE
//    private static KeyPair createKeyPairWithJCA() throws NoSuchAlgorithmException {
//        CertificateFactory certificateFactory = new CertificateFactory();
//
//
//
//
//
//        SecureRandom sr = new SecureRandom();
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//        keyGen.initialize(1024, sr);
//        KeyPair keypair = keyGen.generateKeyPair();
//        PrivateKey privKey = keypair.getPrivate();
//        PublicKey pubKey = keypair.getPublic();
//        KeyPair keyPair = new KeyPair(pubKey, privKey);
//        return keyPair;
//    }

//    // Create Certificate
//    private static void createCert() {
//        Calendar expiry = Calendar.getInstance();
//        expiry.add(Calendar.DAY_OF_YEAR, validityDays);
//
//        X509Name x509Name = new X509Name(“CN=” + dn);
//
//        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
//        certGen.setSerialNumber(new DERInteger(BigInteger.valueOf(System.currentTimeMillis())));
//        certGen.setIssuer(PrincipalUtil.getSubjectX509Principal(caCert));
//        certGen.setSubject(x509Name);
//        DERObjectIdentifier sigOID = X509Util.getAlgorithmOID("SHA1WithRSAEncryption");
//        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(sigOID, new DERNull());
//        certGen.setSignature(sigAlgId);
//        certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
//                new ByteArrayInputStream(pubKey.getEncoded())).readObject()));
//        certGen.setStartDate(new Time(new Date(System.currentTimeMillis())));
//        certGen.setEndDate(new Time(expiry.getTime()));
//        TBSCertificateStructure tbsCert = certGen.generateTBSCertificate();
//    }


}
