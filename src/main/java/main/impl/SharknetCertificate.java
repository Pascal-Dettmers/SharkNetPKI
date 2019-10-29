package main.impl;

import main.interfaces.SharknetCertificateInterface;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class SharknetCertificate implements Serializable, Comparable<SharknetCertificateInterface>, SharknetCertificateInterface {

    private String alias;
    private String uuid;
    private Certificate certificate;

    public SharknetCertificate(String alias, String uuid, Certificate certificate) throws CertificateException {
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

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    @Override
    public int compareTo(SharknetCertificateInterface o) {
        return this.uuid.compareTo(o.getUuid());
    }

    @Override
    public boolean equals(Object obj) {
        boolean result = false;

        if (obj instanceof SharknetCertificate) {
            SharknetCertificateInterface cert = (SharknetCertificateInterface) obj;
            result = cert.getUuid().equals(this.uuid);
        }
        return result;
    }
}
