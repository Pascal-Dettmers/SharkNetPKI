package main.de.htw.berlin.s0551733.sharknetpki;

import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetException;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.PKI;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.SharkNetCertificate;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.SharkNetPublicKey;
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
import java.util.*;

public class SharkNetPKI implements PKI {

    private HashSet<SharkNetPublicKey> sharkNetPublicKeys;
    private HashSet<SharkNetCertificate> sharkNetCertificates;
    private KeyStore keyStore;
    private InputStream inputStream;

    private static final int DURATION_YEARS = 2;
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEYSTORE_PROVIDER = "BC";
    private static final String KEYSTORE_KEY_ALIAS = "key1";

    private char[] password;
    private static SharkNetPKI sharkNetSingleton;

    /**
     * Return Instance of PKI
     *
     * @return
     */
    public static SharkNetPKI getInstance() {
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
    public synchronized static SharkNetPKI init(char[] password, InputStream inputStream) throws SharkNetException {
        if (sharkNetSingleton != null) {
            throw new AssertionError("Already initialized");
        }

        sharkNetSingleton = new SharkNetPKI(password, inputStream);
        return sharkNetSingleton;
    }

    /**
     * Initialize PKI with given Public Keys an Certificates. Need to be done before the PKI can be used. Important, if you never persist the keystore, the input stream has to be null!
     *
     * @param keyStorePassword     Password for Keystore
     * @param sharkNetPublicKeys   List of Public Keys that the PKI should manage
     * @param sharkNetCertificates List of Certifcates that the PKI should manage
     * @return Initialized instance PKI
     * @throws SharkNetException
     */
    public synchronized static SharkNetPKI init(char[] keyStorePassword, InputStream inputStream, HashSet<SharkNetPublicKey> sharkNetPublicKeys, HashSet<SharkNetCertificate> sharkNetCertificates) throws SharkNetException {
        if (sharkNetSingleton != null) {
            throw new AssertionError("Already initialized");
        }

        sharkNetSingleton = new SharkNetPKI(keyStorePassword, inputStream, sharkNetPublicKeys, sharkNetCertificates);
        return sharkNetSingleton;
    }

    private SharkNetPKI(char[] password, InputStream inputStream) throws SharkNetException {
        this(password, inputStream, new HashSet<SharkNetPublicKey>(), new HashSet<SharkNetCertificate>());

    }

    private SharkNetPKI(char[] keyStorePassword, InputStream inputStream, HashSet<SharkNetPublicKey> sharkNetPublicKeys, HashSet<SharkNetCertificate> sharkNetCertificates) throws SharkNetException {
        this.sharkNetPublicKeys = sharkNetPublicKeys;
        this.sharkNetCertificates = sharkNetCertificates;
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
        for (SharkNetPublicKey key : sharkNetPublicKeys) {
            users.add(key.getOwner());
        }
        for (SharkNetCertificate cert : sharkNetCertificates) {
            users.add(cert.getSubject());
        }
        return users;
    }

    /**
     * Returns specific Public Key from given uuid
     *
     * @param uuid Uuid from public Key owner
     * @return Public Key from owner with given uuid
     */
    public PublicKey getPublicKey(String uuid) {
        PublicKey wantedKey = null;
        for (SharkNetPublicKey key : sharkNetPublicKeys) {
            if (key.getOwner().getUuid().equals(uuid)) {
                wantedKey = key.getPublicKey();
                break;
            }
        }
        if (wantedKey == null) {
            for (SharkNetCertificate cert : sharkNetCertificates) {
                if (cert.getSubject().getUuid().equals(uuid)) {
                    wantedKey = cert.getCertificate().getPublicKey();
                    break;
                }
            }
        }
        return wantedKey;
    }

    /**
     * Returns all Sharknet Public Keys
     *
     * @return HashSet of all sharknet Public Keys
     */
    public HashSet<SharkNetPublicKey> getSharkNetPublicKeys() {
        return this.sharkNetPublicKeys;
    }

    /**
     * Returns all Certificates from the PKI
     *
     * @return HashSet of Certificates in the PKI
     */
    @Override
    public HashSet<SharkNetCertificate> getSharkNetCertificates() {
        return this.sharkNetCertificates;
    }

    /**
     * Return Certificate with given uuid
     *
     * @param uuid Uuid from subject of the Certificate
     * @return Certificate with given uuid
     */
    public SharkNetCertificate getCertificate(String uuid) {
        SharkNetCertificate wantedCertificate = null;
        for (SharkNetCertificate cert : sharkNetCertificates) {
            if (cert.getSubject().getUuid().equals(uuid)) {
                wantedCertificate = cert;
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
    public void addCertificate(SharkNetCertificate certificate) {
        sharkNetCertificates.add(certificate);
    }

    /**
     * Add Public Key to PKI
     *
     * @param publicKey Public Key to add
     */
    @Override
    public void addPublicKey(SharkNetPublicKey publicKey) {
        sharkNetPublicKeys.add(publicKey);
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
    public X509Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey, String issuer, String subject) throws SharkNetException {

        Certificate certificate = null;

        try {
            // define expiry date
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            //Jahr von heute plus YEAR Jahre
            end.add(Calendar.YEAR, DURATION_YEARS);

            // define issuer
            X500Name issuerName = new X500Name("CN=" + issuer);
            // define subject
            X500Name subjectName = new X500Name("CN=" + subject);
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            // publicKeyInfo the info structure for the public key to be associated with this certificate
            SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            // create certificate
            X509v3CertificateBuilder cert = new X509v3CertificateBuilder(issuerName, serialNumber, start.getTime(), end.getTime(), subjectName, subPubKeyInfo);
            // sign certificate
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
            ContentSigner signer = builder.build(privateKey);

            byte[] certBytes = cert.build(signer).getEncoded();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        } catch (Exception e) {
            throw new SharkNetException(e);
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
    public VerifySignatureResult verifySignature(Certificate certToVerify, PublicKey potentialSignerPublicKey) {
        try {
            certToVerify.verify(potentialSignerPublicKey);
        } catch (Exception e) {
            if (e instanceof InvalidKeyException) {
                return VerifySignatureResult.INVALID_KEY;
            }
            if (e instanceof SignatureException) {
                return VerifySignatureResult.SIGNATURE_ERROR;
            } else {
                return VerifySignatureResult.UNKNOWN_ERROR;
            }
        }

        return VerifySignatureResult.VERIFIED;
    }

    /**
     * Removed Public Key from PKI
     *
     * @param publicKey Public Key to remove
     */
    @Override
    public void removePublicKey(SharkNetPublicKey publicKey) {
        this.sharkNetPublicKeys.remove(publicKey);
    }

    /**
     * Removed Certificate from PKI
     *
     * @param certificate Certificate to remove
     */
    @Override
    public void removeCertificate(SharkNetCertificate certificate) {
        this.sharkNetCertificates.remove(certificate);
    }

    /**
     * Return Users own Private Key
     *
     * @return Users own Private Key
     */
    public PrivateKey getPrivateKey() throws SharkNetException {
        Key privateKey = null;
        try {
            privateKey = keyStore.getKey("key1", this.password);
        } catch (Exception e) {
            throw new SharkNetException(e);
        }
        return (PrivateKey) privateKey;

    }

    /**
     * Persist Keystore to the output stream given path
     *
     * @param outputStream output Stream with given path
     */
    public void persistKeyStore(OutputStream outputStream) throws SharkNetException {
        try {
            this.keyStore.store(outputStream, this.password);
        } catch (Exception e) {
            throw new SharkNetException(e);
        }
    }

    private void loadKeystore() throws SharkNetException {
        // Android dont support JKS as keystoretype, https://stackoverflow.com/questions/44448970/bouncycastle-nosuchproviderexception-even-though-its-a-maven-dependency
        // if provider is not present, add it , https://stackoverflow.com/questions/44448970/bouncycastle-nosuchproviderexception-even-though-its-a-maven-dependency
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            // insert at specific position
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        try {

            this.keyStore = KeyStore.getInstance(KEYSTORE_TYPE, KEYSTORE_PROVIDER);

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

    private void initKeyStore() throws SharkNetException {

        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.insertProviderAt(new BouncyCastleProvider(), 1);
            }
            this.keyStore = KeyStore.getInstance(KEYSTORE_TYPE, KEYSTORE_PROVIDER);
            this.keyStore.load(null);

            KeyPair keyPair = createKeyPair();

            X509Certificate certificate = generateCertificate(keyPair.getPublic(), keyPair.getPrivate(), "localhost", "localhost");

            Certificate[] certChain = new Certificate[1];
            certChain[0] = certificate;

            KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), certChain);
            this.keyStore.setEntry(KEYSTORE_KEY_ALIAS, privateKeyEntry, new KeyStore.PasswordProtection(this.password));

        } catch (Exception e) {
            throw new SharkNetException(e);
        }
    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {
        SecureRandom secRandom = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secRandom);

        return keyGen.generateKeyPair();
    }

//    public SharkNetPublicKey generateMyOwnSharkNetPublicKey
}
