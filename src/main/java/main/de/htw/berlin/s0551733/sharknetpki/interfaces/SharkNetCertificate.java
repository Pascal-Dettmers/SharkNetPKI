package main.de.htw.berlin.s0551733.sharknetpki.interfaces;

import java.security.cert.Certificate;

public interface SharkNetCertificate {

    User getSubject();
    Certificate getCertificate();
    User getSigner();
}
