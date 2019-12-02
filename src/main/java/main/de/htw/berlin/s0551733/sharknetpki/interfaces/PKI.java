package main.de.htw.berlin.s0551733.sharknetpki.interfaces;

import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetUser;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;

public interface PKI {

    List<User> getUsers();

    PublicKey getPublicKey(String uuid);

    Certificate getCertificate(String uuid);

    HashSet<SharknetPublicKey> getPublicKeys();

    HashSet<SharknetCertificate> getCertificates();

    void addCertificate(SharknetCertificate certificate);

    void addPublicKey(SharknetPublicKey publicKey);

    boolean verifySignature(Certificate certToVerify, PublicKey potentialSignerPublicKey);

    void removePublicKey(SharknetPublicKey publicKey);

    void removeCertificate(SharknetCertificate certificate);

    PublicKey getMyOwnPublicKey() throws KeyStoreException;

    X509Certificate generateCertificate(PublicKey publicKeyFromSubject, PrivateKey privateKeyFromIssuer, String issuer, String subject) throws IOException, OperatorCreationException, CertificateException;

}
