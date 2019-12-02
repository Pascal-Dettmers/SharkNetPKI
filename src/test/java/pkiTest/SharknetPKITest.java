package pkiTest;

import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetException;
import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetUser;
import main.de.htw.berlin.s0551733.sharknetpki.impl.SharknetPKI;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.PKI;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.SharknetCertificate;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.SharknetPublicKey;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.User;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pkiTest.implementations.SharknetCertificateImpl;
import pkiTest.implementations.SharknetPublicKeyImpl;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

class SharknetPKITest {

    private KeyPair keypairA;
    private KeyPair keypairB;
    private KeyPair keypairC;
    private KeyPair keypairD;

    private SharknetPublicKey publicKeyA;
    private SharknetPublicKey publicKeyB;
    private SharknetPublicKey publicKeyC;
    private SharknetPublicKey publicKeyD;

    private ArrayList<User> userList;

    private FileInputStream fileInputStream;

    private String path;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {

        // Create Keypair's
        SecureRandom secRandom = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secRandom);
        keypairA = keyGen.generateKeyPair();

        SecureRandom secRandomB = new SecureRandom();
        KeyPairGenerator keyGenB = KeyPairGenerator.getInstance("RSA");
        keyGenB.initialize(2048, secRandomB);
        keypairB = keyGen.generateKeyPair();

        SecureRandom secRandomC = new SecureRandom();
        KeyPairGenerator keyGenC = KeyPairGenerator.getInstance("RSA");
        keyGenC.initialize(2048, secRandomC);
        keypairC = keyGen.generateKeyPair();

        SecureRandom secRandomD = new SecureRandom();
        KeyPairGenerator keyGenD = KeyPairGenerator.getInstance("RSA");
        keyGenD.initialize(2048, secRandomD);
        keypairD = keyGen.generateKeyPair();

        SharkNetUser publicKeyAUser = new SharkNetUser("123", "publicKeyA");
        SharkNetUser publicKeyBUser = new SharkNetUser("456", "publicKeyB");
        SharkNetUser publicKeyCUser = new SharkNetUser("789", "publicKeyC");
        SharkNetUser publicKeyDUser = new SharkNetUser("101112", "publicKeyD");
        userList = new ArrayList<>();
        userList.add(publicKeyAUser);
        userList.add(publicKeyBUser);
        userList.add(publicKeyCUser);
        userList.add(publicKeyDUser);

        Path resourceDirectory = Paths.get("src","test","resources", "keystore.ks");
        String absolutePath = resourceDirectory.toFile().getAbsolutePath();

        path = absolutePath;

        try {
            fileInputStream = new FileInputStream(path);
        } catch (FileNotFoundException e) {
            fileInputStream = null;
        }


    }

    @Test
    void initWithoutSets() throws SharkNetException {
        SharknetPKI sharknetPKI = SharknetPKI.init("password".toCharArray(), fileInputStream);
        assertNotNull(sharknetPKI);
    }

    @Test
    void initWithEmptySets() throws SharkNetException {
        HashSet<SharknetPublicKey> sharknetPublicKeys = new HashSet<>();
        HashSet<SharknetCertificate> sharknetCertificates = new HashSet<>();
        SharknetPKI sharknetPKI = SharknetPKI.init("password".toCharArray(), fileInputStream, sharknetPublicKeys, sharknetCertificates);

        assertNotNull(sharknetPKI);
        assertEquals(sharknetPKI.getPublicKeys(), sharknetPublicKeys);
        assertEquals(sharknetPKI.getCertificates(), sharknetCertificates);
    }

    @Test
    void initWithInitializedSets() throws SharkNetException, CertificateException, OperatorCreationException, IOException {
        HashSet<SharknetPublicKey> sharknetPublicKeys = generateSharknetPublicKeys();
        HashSet<SharknetCertificate> sharknetCertificates = generateSharknetCertificates();
        SharknetPKI sharknetPKI = SharknetPKI.init("password".toCharArray(), fileInputStream, sharknetPublicKeys, sharknetCertificates);

        assertNotNull(sharknetPKI);
        assertEquals(sharknetPKI.getPublicKeys(), sharknetPublicKeys);
        assertEquals(sharknetPKI.getCertificates(), sharknetCertificates);
    }

    @Test
    void generateCertificate() throws CertificateException, OperatorCreationException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, SharkNetException {

        PKI sharknetPKI = SharknetPKI.init("pw".toCharArray(), fileInputStream);
        X509Certificate x509CertificateC = sharknetPKI.generateCertificate(keypairC.getPublic(), keypairA.getPrivate(), "KeypairA", "KeypairC");

        assertNotNull(x509CertificateC);
        assertEquals(x509CertificateC.getPublicKey(), keypairC.getPublic());
        assertEquals("CN=KeypairA", x509CertificateC.getIssuerDN().getName());
        assertEquals("CN=KeypairC", x509CertificateC.getSubjectDN().getName());
        x509CertificateC.verify(keypairA.getPublic());

    }

    @Test
    void verifySignature() throws SharkNetException {

        SharknetPKI sharknetPKI = SharknetPKI.init("password".toCharArray(), fileInputStream);
        X509Certificate x509CertificateC = sharknetPKI.generateCertificate(keypairC.getPublic(), keypairA.getPrivate(), "KeypairA", "KeypairC");

        assertTrue(sharknetPKI.verifySignature(x509CertificateC, keypairA.getPublic()));

    }

    @Test
    void verifySignatureWrongPubKey() throws SharkNetException {
        SharknetPKI sharknetPKI = SharknetPKI.init("password".toCharArray(), fileInputStream);
        X509Certificate x509CertificateC = sharknetPKI.generateCertificate(keypairC.getPublic(), keypairA.getPrivate(), "KeypairA", "KeypairC");

        // keypairB instead of KeypairA
        assertFalse(sharknetPKI.verifySignature(x509CertificateC, keypairB.getPublic()));
    }

    @Test
    void persistKeyStoreForTheFirstTime() throws SharkNetException {

        SharknetPKI sharknetPKI = SharknetPKI.init("password".toCharArray(), fileInputStream);
        try {
            sharknetPKI.persistKeyStore(new FileOutputStream(path));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        File temp;
        temp = new File(path);
        assertTrue(temp.exists());
        temp.delete();
    }

    @Test
    void persistExistingKeyStore() throws SharkNetException {

        SharknetPKI sharknetPKI = SharknetPKI.init("password".toCharArray(), fileInputStream);
        try {
            // Create Keystore for the first time
            sharknetPKI.persistKeyStore(new FileOutputStream(path));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        // Change fileinput to existing Keystore file
        try {
            fileInputStream = new FileInputStream(path);
        } catch (FileNotFoundException e) {
            fileInputStream = null;
        }

        // Override existing keystore
        try {
            sharknetPKI.persistKeyStore(new FileOutputStream(path));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        File temp;
        temp = new File(path);
        assertTrue(temp.exists());
        temp.delete();
    }

    @Test
    void loadKeyStore() throws NoSuchMethodException, SharkNetException, NoSuchFieldException, InvocationTargetException, IllegalAccessException, FileNotFoundException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        // For testing private Methods
        Method method = SharknetPKI.class.getDeclaredMethod("loadKeystore");
        method.setAccessible(true);

        // init SharknetPKI
        SharknetPKI sharknetPKI = SharknetPKI.init("password".toCharArray(), fileInputStream);

        // For testing private Attributes
        Field keyStoreFieldA = sharknetPKI.getClass().getDeclaredField("keyStore");
        keyStoreFieldA.setAccessible(true);
        KeyStore keyStoreA = (KeyStore) keyStoreFieldA.get(sharknetPKI);


        try {
            // Create Keystore for the first time
            sharknetPKI.persistKeyStore(new FileOutputStream(path));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        // For testing private Attributes
        Field inputStreamField = sharknetPKI.getClass().getDeclaredField("inputStream");
        inputStreamField.setAccessible(true);
        inputStreamField.set(sharknetPKI,new FileInputStream(path));

        method.invoke(sharknetPKI);

        // For testing private Attributes
        Field keyStoreFieldB = sharknetPKI.getClass().getDeclaredField("keyStore");
        keyStoreFieldB.setAccessible(true);
        KeyStore keyStoreB = (KeyStore) keyStoreFieldB.get(sharknetPKI);

        File temp;
        temp = new File(path);
        assertTrue(temp.exists());
        temp.delete();

        assertEquals(keyStoreA.getCertificate("key1"), keyStoreB.getCertificate("key1"));
        assertEquals(keyStoreA.getKey("key1","password".toCharArray()), keyStoreB.getKey("key1","password".toCharArray()));
    }


    @Test
    void getUsers() {

    }

    @Test
    void getPublicKey() {
    }

    @Test
    void getPublicKeys() {
    }

    @Test
    void getCertificates() {
    }

    @Test
    void getCertificate() {
    }

    @Test
    void addCertificate() {
    }

    @Test
    void addPublicKey() {
    }

    @Test
    void getMyOwnPublicKey() {
    }

    @Test
    void removePublicKey() {
    }

    @Test
    void removeCertificate() {
    }

    @Test
    void getPrivateKey() {
    }


    private HashSet<SharknetCertificate> generateSharknetCertificates() throws CertificateException, OperatorCreationException, SharkNetException, IOException {
        PKI sharknetPKI = SharknetPKI.init("pw".toCharArray(), fileInputStream);


        publicKeyC = new SharknetPublicKeyImpl(new SharkNetUser("789", "publicKeyC"), this.keypairC.getPublic(), new Date());
        publicKeyD = new SharknetPublicKeyImpl(new SharkNetUser("101112", "publicKeyD"), this.keypairD.getPublic(), new Date());

        // Create Certs signed from publicKeyA
        X509Certificate x509CertificateC = sharknetPKI.generateCertificate(keypairC.getPublic(), keypairA.getPrivate(), "KeypairA", "KeypairC");
        X509Certificate x509CertificateD = sharknetPKI.generateCertificate(keypairD.getPublic(), keypairA.getPrivate(), "KeypairA", "KeypairD");

        SharknetCertificate certC = new SharknetCertificateImpl(publicKeyC.getOwner(), x509CertificateC, publicKeyA.getOwner());
        SharknetCertificate certD = new SharknetCertificateImpl(publicKeyD.getOwner(), x509CertificateD, publicKeyA.getOwner());

        HashSet<SharknetCertificate> sharknetCertificates = new HashSet<>();
        sharknetCertificates.add(certC);
        sharknetCertificates.add(certD);

        return sharknetCertificates;

    }

    private HashSet<SharknetPublicKey> generateSharknetPublicKeys() {
        publicKeyA = new SharknetPublicKeyImpl(new SharkNetUser("123", "publicKeyA"), this.keypairA.getPublic(), new Date());
        publicKeyB = new SharknetPublicKeyImpl(new SharkNetUser("456", "publicKeyB"), this.keypairB.getPublic(), new Date());

        HashSet<SharknetPublicKey> publicKeys = new HashSet<>();
        publicKeys.add(publicKeyA);
        publicKeys.add(publicKeyB);

        return publicKeys;
    }
}