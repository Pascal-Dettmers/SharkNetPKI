package main.de.htw.berlin.s0551733.sharknetpki.impl;

import main.de.htw.berlin.s0551733.sharknetpki.PKI;
import main.de.htw.berlin.s0551733.sharknetpki.SharknetCertificate;
import main.de.htw.berlin.s0551733.sharknetpki.SharknetPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class SharknetPKI implements PKI {

    private HashSet<SharknetPublicKey> sharknetPublicKeys;
    private HashSet<SharknetCertificate> sharknetCertificates;
    private KeyStore keyStore;

    private static final int DURATION_YEARS = 1;
    private char[] password;
    private static SharknetPKI sharkNetSingleton;

    /**
     * Return Instance of PKI
     * @return
     */
    public static SharknetPKI getInstance() {
        if (sharkNetSingleton == null) {
            throw new AssertionError("You have to call init first");
        }
        return sharkNetSingleton;
    }

    /**
     * Initialize PKI with empty Public Keys and Certificates
     * @param password Password for Keystore
     * @return Initialized instance PKI
     * @throws SharkNetException
     */
    public synchronized static SharknetPKI init(char[] password) throws SharkNetException {
        if (sharkNetSingleton != null) {
            throw new AssertionError("Already initialized");
        }

        sharkNetSingleton = new SharknetPKI(password);
        return sharkNetSingleton;
    }

    /**
     * Initialize PKI with given Public Keys an Certificates. Need to be done before PKI can be used
     * @param keyStorePassword Password for Keystore
     * @param sharknetPublicKeys List of Public Keys that the PKI should manage
     * @param sharknetCertificates List of Certifcates that the PKI should manage
     * @return Initialized instance PKI
     * @throws SharkNetException
     */
    public synchronized static SharknetPKI init(char[] keyStorePassword, HashSet<SharknetPublicKey> sharknetPublicKeys, HashSet<SharknetCertificate> sharknetCertificates) throws SharkNetException {
        if (sharkNetSingleton != null) {
            throw new AssertionError("Already initialized");
        }

        sharkNetSingleton = new SharknetPKI(keyStorePassword, sharknetPublicKeys, sharknetCertificates);
        return sharkNetSingleton;
    }

    /**
     * Return all Users in PKI
     * @return List of Users in PKI
     */
    public List<SharkNetUser> getUsers() {
        final List<SharkNetUser> users = new ArrayList<>();
        for (SharknetPublicKey key : sharknetPublicKeys) {
            users.add(new SharkNetUser(key.getUuid(), key.getAlias()));
        }
        for (SharknetCertificate cert : sharknetCertificates) {
            users.add(new SharkNetUser(cert.getUuid(), cert.getAlias()));
        }
        return users;
    }

    /**
     * Returns specific Public Key from from given uuid
     * @param uuid Uuid from public Key owner
     * @return Public Key from owner with given uuid
     */
    public PublicKey getPublicKey(String uuid) {
        PublicKey wantedKey = null;
        for (SharknetPublicKey key : sharknetPublicKeys) {
            if (key.getUuid().equals(uuid)) {
                wantedKey = key.getPublicKey();
                break;
            }
        }
        if (wantedKey == null) {
            for (SharknetCertificate cert : sharknetCertificates) {
                if (cert.getUuid().equals(uuid)) {
                    wantedKey = cert.getCertificate().getPublicKey();
                    break;
                }
            }
        }
        return wantedKey;
    }

    /**
     * Returns all Public Keys from the PKI
     * @return HashSet of Public Keys in the PKI
     */
    @Override
    public HashSet<SharknetPublicKey> getPublicKeys() {
        return this.sharknetPublicKeys;
    }

    /**
     * Returns all Certificates from the PKI
     * @return HashSet of Certificates in the PKI
     */
    @Override
    public HashSet<SharknetCertificate> getCertificates() {
        return this.sharknetCertificates;
    }

    /**
     * Return Certificate with given uuid
     * @param uuid Uuid from subject of the Certificate
     * @return Certificate with given uuid
     */
    public Certificate getCertificate(String uuid) {
        Certificate wantedCertificate = null;
        for (SharknetCertificate cert : sharknetCertificates) {
            if (cert.getUuid().equals(uuid)) {
                wantedCertificate = cert.getCertificate();
                break;
            }
        }
        return wantedCertificate;
    }

    /**
     * Add Certificate to PKI
     * @param certificate Certificate to add
     */
    public void addCertificate(SharknetCertificate certificate) {
        sharknetCertificates.add(certificate);
    }

    /**
     * Add Public Key to PKI
     * @param publicKey Public Key to add
     */
    @Override
    public void addPublicKey(SharknetPublicKey publicKey) {
        sharknetPublicKeys.add(publicKey);
    }

    /**
     * Generates a Certificate for a given Public Key with a given Private Key
     * @param publicKey Subject Public Key
     * @param privateKey Signer Private Key
     * @param issuer Who creates the Certificate
     * @param subject Public Key owner
     * @return Certificate for a given Public Key
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    public X509Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey, String issuer, String subject) throws IOException, OperatorCreationException, CertificateException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        //Jahr von heute plus YEAR Jahre
        end.add(Calendar.YEAR, DURATION_YEARS);

        X500Name issuerName = new X500Name("CN=" + issuer);
        X500Name subjectName = new X500Name("CN=" + subject);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X509v3CertificateBuilder cert = new X509v3CertificateBuilder(issuerName, serialNumber, start.getTime(), end.getTime(), subjectName, subPubKeyInfo);
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = builder.build(privateKey);

        byte[] certBytes = cert.build(signer).getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    /**
     * Returns the own Public Key
     * @return Public Key
     * @throws KeyStoreException
     */
    @Override
    public PublicKey getMyOwnPublicKey() throws KeyStoreException {
        return keyStore.getCertificate("key1").getPublicKey();
    }

    /**
     * Verified Signatur of Certificate
     * @param certToVerify Signed Certificate
     * @param potentialSignerPublicKey Potential Signer Public Key
     * @return true if Signature could verified
     */
    @Override
    public boolean verifySignature(Certificate certToVerify, PublicKey potentialSignerPublicKey) {
        boolean result = true;
        try {
            certToVerify.verify(potentialSignerPublicKey);
        } catch (Exception e) {
            if (e instanceof InvalidKeyException) {
                System.out.println("wrong Key");
                return !result;
            }
            if (e instanceof SignatureException) {
                System.out.println("Signature error");
                return !result;
            } else {
                return !result;
            }
        }

        return result;
    }

    /**
     * Removed Public Key from PKI
     * @param publicKey Public Key to remove
     */
    @Override
    public void removePublicKey(SharknetPublicKey publicKey) {
        this.sharknetPublicKeys.remove(publicKey);
    }

    /**
     * Removed Certificate from PKI
     * @param certificate Certificate to remove
     */
    @Override
    public void removeCertificate(SharknetCertificate certificate) {
        this.sharknetCertificates.remove(certificate);
    }

    /**
     * Return Users own Private Key
     * @return Users own Private Key
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public PrivateKey getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return (PrivateKey) keyStore.getKey("key1", this.password);

    }

    /**
     * Persist Keystore to the output stream given path
     * @param outputStream output Stream with given path
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     */
    public void persistKeyStore(OutputStream outputStream) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.keyStore.store(outputStream, this.password);
    }

    /**
     * Load the Key Store from the input stream given path
     * @param inputStream input stream with given path
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public void loadKeyStore(InputStream inputStream) throws CertificateException, NoSuchAlgorithmException, IOException {
        keyStore.load(inputStream, this.password);
    }

    private SharknetPKI(char[] password) throws SharkNetException {
        this(password, new HashSet<SharknetPublicKey>(), new HashSet<SharknetCertificate>());
    }

    private SharknetPKI(char[] keyStorePassword, HashSet<SharknetPublicKey> sharknetPublicKeys, HashSet<SharknetCertificate> sharknetCertificates) throws SharkNetException {
        this.sharknetPublicKeys = sharknetPublicKeys;
        this.sharknetCertificates = sharknetCertificates;
        this.password = keyStorePassword;
        try {
            initKeyStore();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | NoSuchProviderException e) {
            throw new SharkNetException(e);
        }
    }


    private void initKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
        // Android dont support JKS as keystoretype, https://stackoverflow.com/questions/44448970/bouncycastle-nosuchproviderexception-even-though-its-a-maven-dependency
        // if provider is not present, add it , https://stackoverflow.com/questions/44448970/bouncycastle-nosuchproviderexception-even-though-its-a-maven-dependency
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            // insert at specific position
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        this.keyStore = KeyStore.getInstance("BKS", "BC");
        this.keyStore.load(null);

        KeyPair keyPair = createKeyPair();

        X509Certificate certificate = null;
        try {
            certificate = generateCertificate(keyPair.getPublic(), keyPair.getPrivate(), "localhost", "localhost");
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }

        Certificate[] certChain = new Certificate[1];
        certChain[0] = certificate;

        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), certChain);
        this.keyStore.setEntry("key1", privateKeyEntry, new KeyStore.PasswordProtection(this.password));
    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {
        SecureRandom secRandom = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secRandom);

        return keyGen.generateKeyPair();
    }

}
