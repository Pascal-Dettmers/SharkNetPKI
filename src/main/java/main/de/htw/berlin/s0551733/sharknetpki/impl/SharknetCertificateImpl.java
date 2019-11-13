package main.de.htw.berlin.s0551733.sharknetpki.impl;

import main.de.htw.berlin.s0551733.sharknetpki.SharknetCertificate;
import main.de.htw.berlin.s0551733.sharknetpki.User;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Objects;

public class SharknetCertificateImpl implements Serializable, SharknetCertificate {

    private String alias;
    private final String uuid;
    private Certificate certificate;
    private User signer;

    public SharknetCertificateImpl(String alias, String uuid, Certificate certificate)  {
        this.alias = alias;
        this.uuid = uuid;
        this.certificate = certificate;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getUuid() {
        return uuid;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    @Override
    public User getSigner() {
        return signer;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SharknetCertificateImpl that = (SharknetCertificateImpl) o;
        return Objects.equals(uuid, that.uuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uuid);
    }
}
