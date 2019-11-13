package main.de.htw.berlin.s0551733.sharknetpki;

import java.security.cert.Certificate;

public interface SharknetCertificate {

    String getAlias();
    String getUuid();
    Certificate getCertificate();
    User getSigner();
}
