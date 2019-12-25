package main.de.htw.berlin.s0551733.sharknetpki.impl;

import main.de.htw.berlin.s0551733.sharknetpki.interfaces.SharknetCertificate;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.User;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Objects;

public class SharknetCertificateImpl implements Serializable, SharknetCertificate {

    private User subject;
    private Certificate certificate;
    private User signer;

    public SharknetCertificateImpl(User subject, Certificate certificate, User signer) {
        this.subject = subject;
        this.certificate = certificate;
        this.signer = signer;
    }

    @Override
    public User getSubject() {
        return subject;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    @Override
    public User getSigner() {
        return signer;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SharknetCertificateImpl that = (SharknetCertificateImpl) o;
        return Objects.equals(this.subject, that.subject.getUuid());
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject.getUuid());
    }
}
