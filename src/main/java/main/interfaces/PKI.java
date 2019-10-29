package main.interfaces;

import main.impl.SharknetCertificate;
import main.impl.User;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;

public interface PKI {

    List<User> getUsers();

    PublicKey getPublicKey(String uui);

    Certificate getCertificate(String uuid);

    void addCertificate(SharknetCertificate certificate);

}
