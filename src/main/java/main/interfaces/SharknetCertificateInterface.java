package main.interfaces;

import java.security.cert.Certificate;

public interface SharknetCertificateInterface {

    String getAlias();
    String getUuid();
    Certificate getCertificate();
    boolean equals(Object obj);
}
