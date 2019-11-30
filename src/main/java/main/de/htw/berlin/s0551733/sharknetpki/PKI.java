package main.de.htw.berlin.s0551733.sharknetpki;

import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetUser;

import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.HashSet;
import java.util.List;

public interface PKI {

    List<SharkNetUser> getUsers();

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


}
