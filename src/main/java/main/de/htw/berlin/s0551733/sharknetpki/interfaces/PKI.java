package main.de.htw.berlin.s0551733.sharknetpki.interfaces;

import main.de.htw.berlin.s0551733.sharknetpki.VerifySignaturResult;
import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetException;
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

    SharkNetCertificate getCertificate(String uuid);

    HashSet<SharkNetPublicKey> getSharkNetPublicKeys();

    HashSet<SharkNetCertificate> getSharkNetCertificates();

    void addCertificate(SharkNetCertificate certificate);

    void addPublicKey(SharkNetPublicKey publicKey);

    VerifySignaturResult verifySignature(Certificate certToVerify, PublicKey potentialSignerPublicKey);

    void removePublicKey(SharkNetPublicKey publicKey);

    void removeCertificate(SharkNetCertificate certificate);

    PublicKey getMyOwnPublicKey() throws KeyStoreException;

    X509Certificate generateCertificate(PublicKey publicKeyFromSubject, PrivateKey privateKeyFromIssuer, String issuer, String subject) throws IOException, OperatorCreationException, CertificateException, SharkNetException;

}
