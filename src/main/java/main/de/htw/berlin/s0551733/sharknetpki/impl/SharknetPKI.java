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

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class SharknetPKI implements PKI {

    private Set<SharknetPublicKey> sharknetPublicKeys;
    private Set<SharknetCertificate> sharknetCertificates;
    private KeyStore keyStore;
    private static final int KEY_DURATION_YEARS = 1;
    private char[] password;


    private static SharknetPKI sharkNetSingleton = null;

    public static SharknetPKI getInstance() {
        if (sharkNetSingleton == null) {
            throw new AssertionError("You have to call init first");
        }
        return sharkNetSingleton;
    }

    public synchronized static SharknetPKI init(char[] password) throws SharkNetExcption {
        if (sharkNetSingleton != null) {
            throw new AssertionError("Already initialized");
        }

        sharkNetSingleton = new SharknetPKI(password);
        return sharkNetSingleton;
    }

    public synchronized static SharknetPKI init(char[] keyStorePassword, Set<SharknetPublicKey> sharknetPublicKeys, Set<SharknetCertificate> sharknetCertificates) throws SharkNetExcption {
        if (sharkNetSingleton != null) {
            throw new AssertionError("You already initialized me");
        }

        sharkNetSingleton = new SharknetPKI(keyStorePassword, sharknetPublicKeys, sharknetCertificates);
        return sharkNetSingleton;
    }


    private SharknetPKI(char[] password) throws SharkNetExcption {
        this(password, new HashSet<SharknetPublicKey>(), new HashSet<SharknetCertificate>());
    }

    private SharknetPKI(char[] keyStorePassword, Set<SharknetPublicKey> sharknetPublicKeys, Set<SharknetCertificate> sharknetCertificates) throws SharkNetExcption {
        this.sharknetPublicKeys = sharknetPublicKeys;
        this.sharknetCertificates = sharknetCertificates;
        this.password = keyStorePassword;
        try {
            initKeyStore();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | NoSuchProviderException e) {
            throw new SharkNetExcption(e);
        }
    }

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

    public void addCertificate(SharknetCertificateImpl certificate) {
        sharknetCertificates.add(certificate);
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
            certificate = generateCertificateWithCertBuilder(keyPair.getPublic(), keyPair.getPrivate(), "localhost", "localhost");
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


    public X509Certificate generateCertificateWithCertBuilder(PublicKey publicKey, PrivateKey privateKey, String issuer, String subject) throws IOException, OperatorCreationException, CertificateException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        //Jahr von heute plus YEAR Jahre
        end.add(Calendar.YEAR, KEY_DURATION_YEARS);

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


    public PublicKey getPublicKey() throws KeyStoreException {
        return keyStore.getCertificate("key1").getPublicKey();
    }

    public PrivateKey getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return (PrivateKey) keyStore.getKey("key1", this.password);

    }

    public void persistKeyStore(OutputStream outputStream) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
//        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(this.keyStorePath)) {
        this.keyStore.store(outputStream, this.password);
    }

    public void loadKeyStore(InputStream inputStream) throws CertificateException, NoSuchAlgorithmException, IOException {
//        try (InputStream keyStoreData = new FileInputStream(this.keyStorePath)) {
        keyStore.load(inputStream, this.password);
    }
    // BC
//    private KeyPair createKeyPairWithBC() throws NoSuchAlgorithmException, InvalidKeySpecException {
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
//        return new KeyPair(pubKey, privKey);
//    }


//    public X509Certificate generateCertificate(KeyPair keyPair) throws NoSuchAlgorithmException, CertificateEncodingException, InvalidKeyException, SignatureException {
//        Calendar start = Calendar.getInstance();
//        Calendar end = Calendar.getInstance();
//        //Jahr von heute plus YEAR Jahre
//        end.add(Calendar.YEAR, KEY_DURATION_YEARS);
//
//        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
//        cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number
//        cert.setSubjectDN(new X509Principal("CN=localhost"));  //see examples to add O,OU etc
//        cert.setIssuerDN(new X509Principal("CN=localhost")); //same since it is self-signed
//        cert.setPublicKey(keyPair.getPublic());
//        cert.setNotBefore(start.getTime());
//        cert.setNotAfter(end.getTime());
//        cert.setSignatureAlgorithm("SHA256withRSA");
//        PrivateKey signingKey = keyPair.getPrivate();
//        return cert.generate(signingKey);
//    }

//    public X509Certificate generateCertificateForThirdPartyKey(PublicKey publicKey, PrivateKey privateKey) throws NoSuchAlgorithmException, CertificateEncodingException, NoSuchProviderException, InvalidKeyException, SignatureException {
//        Calendar start = Calendar.getInstance();
//        Calendar end = Calendar.getInstance();
//        //Jahr von heute plus YEAR Jahre
//        end.add(Calendar.YEAR, KEY_DURATION_YEARS);
//
//        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
//        cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number
//        cert.setSubjectDN(new X509Principal("CN=localhost"));  //see examples to add O,OU etc
//        cert.setIssuerDN(new X509Principal("CN=thirdParty")); //same since it is self-signed
//        cert.setPublicKey(publicKey);
//        cert.setNotBefore(start.getTime());
//        cert.setNotAfter(end.getTime());
//        cert.setSignatureAlgorithm("SHA256withRSA");
//        PrivateKey signingKey = privateKey;
//        return cert.generate(signingKey);
//    }

//
//    public X509Certificate generate(String dn, KeyPair keyPair) throws CertificateException {
//        try {
//            Security.addProvider(new BouncyCastleProvider());
//            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
//            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
//            AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
//            SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
//            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
//            X500Name name = new X500Name(dn);
//            Date from = new Date();
//            Date to = new Date(from.getTime() + days * 86400000L);
//            BigInteger sn = new BigInteger(64, new SecureRandom());
//            X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(name, sn, from, to, name, subPubKeyInfo);
//
//            if (subjectAltName != null)
//                v3CertGen.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
//            X509CertificateHolder certificateHolder = v3CertGen.build(sigGen);
//            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
//        } catch (CertificateException ce) {
//            throw ce;
//        } catch (Exception e) {
//            throw new CertificateException(e);
//        }
//    }
//
//    private X509Certificate generateCertificateDelta(KeyPair keyPair) throws DeltaClientException {
//        try {
//            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
//            Date startDate = DateTimeUtil.getCurrentDate();
//            Date expiryDate = DateTimeUtil.addDays(startDate, DAYS_CERTIFICATE_VALID);
//            X500Name issuer = new X500Name(ISSUER);
//            X500Name subject = new X500Name(SUBJECT);
//
//            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
//                    issuer, serialNumber, startDate, expiryDate, subject,
//                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
//            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
//            ContentSigner signer = builder.build(keyPair.getPrivate());
//
//
//            byte[] certBytes = certBuilder.build(signer).getEncoded();
//            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
//        } catch (Exception e) {
//            LOG.error(e.getMessage());
//            throw new DeltaClientException("Error generating certificate", e);
//        }
//    }

}
