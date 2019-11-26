package main.de.htw.berlin.s0551733.sharknetpki;

import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetUser;

import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;

public interface PKI {

    List<SharkNetUser> getUsers();

    PublicKey getPublicKey(String uuid);

    Certificate getCertificate(String uuid);

    void addCertificate(SharknetCertificate certificate);

    PublicKey getMyOwnPublicKey() throws KeyStoreException;

    boolean verifySignature(Certificate certToVerify, PublicKey potentialSignerPublicKey);

}
