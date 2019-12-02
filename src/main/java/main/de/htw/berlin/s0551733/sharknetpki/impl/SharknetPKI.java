package main.de.htw.berlin.s0551733.sharknetpki.impl;

import main.de.htw.berlin.s0551733.sharknetpki.interfaces.PKI;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.SharknetCertificate;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.SharknetPublicKey;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.User;
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
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;

public class SharknetPKI implements PKI {

    private HashSet<SharknetPublicKey> sharknetPublicKeys;
    private HashSet<SharknetCertificate> sharknetCertificates;
    private KeyStore keyStore;
    private InputStream inputStream;

    private static final int DURATION_YEARS = 1;
    private char[] password;
    private static SharknetPKI sharkNetSingleton;

    /**
     * Return Instance of PKI
     *
     * @return
     */
    public static SharknetPKI getInstance() {
        if (sharkNetSingleton == null) {
            throw new AssertionError("You have to call init first");
        }
        return sharkNetSingleton;
    }

    /**
     * Initialize PKI with empty Public Keys and Certificates. Need to be done before the PKI can be used. Important, if you never persist the keystore, the input stream has to be null!
     *
     * @param password    Password for Keystore
     * @param inputStream stream to load keystore
     * @return Initialized instance PKI
     * @throws SharkNetException
     */
    public synchronized static SharknetPKI init(char[] password, InputStream inputStream) throws SharkNetException {
        if (sharkNetSingleton != null) {
            throw new AssertionError("Already initialized");
        }

        sharkNetSingleton = new SharknetPKI(password, inputStream);
        return sharkNetSingleton;
    }

    /**
     * Initialize PKI with given Public Keys an Certificates. Need to be done before the PKI can be used. Important, if you never persist the keystore, the input stream has to be null!
     *
     * @param keyStorePassword     Password for Keystore
     * @param sharknetPublicKeys   List of Public Keys that the PKI should manage
     * @param sharknetCertificates List of Certifcates that the PKI should manage
     * @return Initialized instance PKI
     * @throws SharkNetException
     */
    public synchronized static SharknetPKI init(char[] keyStorePassword, InputStream inputStream, HashSet<SharknetPublicKey> sharknetPublicKeys, HashSet<SharknetCertificate> sharknetCertificates) throws SharkNetException {
        if (sharkNetSingleton != null) {
            throw new AssertionError("Already initialized");
        }

        sharkNetSingleton = new SharknetPKI(keyStorePassword, inputStream, sharknetPublicKeys, sharknetCertificates);
        return sharkNetSingleton;
    }

    private SharknetPKI(char[] password, InputStream inputStream) throws SharkNetException {
        this(password, inputStream, new HashSet<SharknetPublicKey>(), new HashSet<SharknetCertificate>());
    }

    private SharknetPKI(char[] keyStorePassword, InputStream inputStream, HashSet<SharknetPublicKey> sharknetPublicKeys, HashSet<SharknetCertificate> sharknetCertificates) throws SharkNetException {
        this.sharknetPublicKeys = sharknetPublicKeys;
        this.sharknetCertificates = sharknetCertificates;
        this.inputStream = inputStream;
        this.password = keyStorePassword;
        loadKeystore();
    }

    /**
     * Return all Users in the PKI
     *
     * @return List of Users in the PKI
     */
    public List<User> getUsers() {
        List<User> users = new ArrayList<>();
        for (SharknetPublicKey key : sharknetPublicKeys) {
            users.add(key.getOwner());
        }
        for (SharknetCertificate cert : sharknetCertificates) {
            users.add(cert.getSubject());
        }
        return users;
    }

    /**
     * Returns specific Public Key from from given uuid
     *
     * @param uuid Uuid from public Key owner
     * @return Public Key from owner with given uuid
     */
    public PublicKey getPublicKey(String uuid) {
        PublicKey wantedKey = null;
        for (SharknetPublicKey key : sharknetPublicKeys) {
            if (key.getOwner().getUuid().equals(uuid)) {
                wantedKey = key.getPublicKey();
                break;
            }
        }
        if (wantedKey == null) {
            for (SharknetCertificate cert : sharknetCertificates) {
                if (cert.getSubject().getUuid().equals(uuid)) {
                    wantedKey = cert.getCertificate().getPublicKey();
                    break;
                }
            }
        }
        return wantedKey;
    }

    /**
     * Returns all Public Keys from the PKI
     *
     * @return HashSet of Public Keys in the PKI
     */
    @Override
    public HashSet<SharknetPublicKey> getPublicKeys() {
        return this.sharknetPublicKeys;
    }

    /**
     * Returns all Certificates from the PKI
     *
     * @return HashSet of Certificates in the PKI
     */
    @Override
    public HashSet<SharknetCertificate> getCertificates() {
        return this.sharknetCertificates;
    }

    /**
     * Return Certificate with given uuid
     *
     * @param uuid Uuid from subject of the Certificate
     * @return Certificate with given uuid
     */
    public Certificate getCertificate(String uuid) {
        Certificate wantedCertificate = null;
        for (SharknetCertificate cert : sharknetCertificates) {
            if (cert.getSubject().getUuid().equals(uuid)) {
                wantedCertificate = cert.getCertificate();
                break;
            }
        }
        return wantedCertificate;
    }

    /**
     * Add Certificate to PKI
     *
     * @param certificate Certificate to add
     */
    public void addCertificate(SharknetCertificate certificate) {
        sharknetCertificates.add(certificate);
    }

    /**
     * Add Public Key to PKI
     *
     * @param publicKey Public Key to add
     */
    @Override
    public void addPublicKey(SharknetPublicKey publicKey) {
        sharknetPublicKeys.add(publicKey);
    }

    /**
     * Generates a Certificate for a given Public Key with a given Private Key
     *
     * @param publicKey  Subject Public Key
     * @param privateKey Signer Private Key
     * @param issuer     Who creates the Certificate
     * @param subject    Public Key owner
     * @return Certificate for a given Public Key
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    public X509Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey, String issuer, String subject) {

        Certificate certificate = null;

        try {
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
            certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return (X509Certificate) certificate;
    }

    /**
     * Returns the own Public Key
     *
     * @return Public Key
     * @throws KeyStoreException
     */
    @Override
    public PublicKey getMyOwnPublicKey() throws KeyStoreException {
        return keyStore.getCertificate("key1").getPublicKey();
    }

    /**
     * Verified Signatur of Certificate
     *
     * @param certToVerify             Signed Certificate
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
                System.out.println("Invalid Key");
                return !result;
            }
            if (e instanceof SignatureException) {
                System.out.println("Signature Exception, are your sure this is the right Subject Public Key");
                return !result;
            } else {
                return !result;
            }
        }

        return result;
    }

    /**
     * Removed Public Key from PKI
     *
     * @param publicKey Public Key to remove
     */
    @Override
    public void removePublicKey(SharknetPublicKey publicKey) {
        this.sharknetPublicKeys.remove(publicKey);
    }

    /**
     * Removed Certificate from PKI
     *
     * @param certificate Certificate to remove
     */
    @Override
    public void removeCertificate(SharknetCertificate certificate) {
        this.sharknetCertificates.remove(certificate);
    }

    /**
     * Return Users own Private Key
     *
     * @return Users own Private Key
     */
    public PrivateKey getPrivateKey() {
        Key privateKey = null;
        try {
            privateKey = keyStore.getKey("key1", this.password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return (PrivateKey) privateKey;

    }

    /**
     * Persist Keystore to the output stream given path
     *
     * @param outputStream output Stream with given path
     */
    public void persistKeyStore(OutputStream outputStream) {
        try {
            this.keyStore.store(outputStream, this.password);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private void loadKeystore() {
        // Android dont support JKS as keystoretype, https://stackoverflow.com/questions/44448970/bouncycastle-nosuchproviderexception-even-though-its-a-maven-dependency
        // if provider is not present, add it , https://stackoverflow.com/questions/44448970/bouncycastle-nosuchproviderexception-even-though-its-a-maven-dependency
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            // insert at specific position
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        try {

            this.keyStore = KeyStore.getInstance("BKS", "BC");


            if (this.inputStream != null) {
                this.keyStore.load(inputStream, password);
            } else {
                initKeyStore();
            }

        } catch (IOException e) {
            initKeyStore();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    private void initKeyStore() {

        try {
            this.keyStore = KeyStore.getInstance("BKS", "BC");
            this.keyStore.load(null);

            KeyPair keyPair = createKeyPair();

            X509Certificate certificate = null;
            certificate = generateCertificate(keyPair.getPublic(), keyPair.getPrivate(), "localhost", "localhost");

            Certificate[] certChain = new Certificate[1];
            certChain[0] = certificate;

            KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), certChain);
            this.keyStore.setEntry("key1", privateKeyEntry, new KeyStore.PasswordProtection(this.password));

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {
        SecureRandom secRandom = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secRandom);

        return keyGen.generateKeyPair();
    }

}
