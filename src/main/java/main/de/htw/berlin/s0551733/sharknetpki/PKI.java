package main.de.htw.berlin.s0551733.sharknetpki;

import main.de.htw.berlin.s0551733.sharknetpki.impl.SharknetCertificateImpl;
import main.de.htw.berlin.s0551733.sharknetpki.impl.SharkNetUser;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;

public interface PKI {

    List<SharkNetUser> getUsers();

    PublicKey getPublicKey(String uui);

    Certificate getCertificate(String uuid);

    void addCertificate(SharknetCertificateImpl certificate);

}
