package com.example.dsvs.entity;

import java.time.Instant;

import jakarta.persistence.*;

@Entity
@Table(name = "key_pairs")
public class KeyPairEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 100)
    private String alias;

    @Column(nullable = false, length = 10)
    private String algorithm;           // RSA or EC

    private int keySize;

    @Column(nullable = false, length = 10000)
    private String publicKey;           // Base64 X.509

    @Column(nullable = false, length = 10000)
    private String encryptedPrivateKey; // Base64 AES-GCM(PKCS#8)

    @Column(nullable = false)
    private String salt;                // Base64 PBKDF2 salt

    @Column(nullable = false)
    private String iv;                  // Base64 GCM IV

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public String getAlias() { return alias; }
    public void setAlias(String alias) { this.alias = alias; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public int getKeySize() { return keySize; }
    public void setKeySize(int keySize) { this.keySize = keySize; }
    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }
    public String getEncryptedPrivateKey() { return encryptedPrivateKey; }
    public void setEncryptedPrivateKey(String v) { this.encryptedPrivateKey = v; }
    public String getSalt() { return salt; }
    public void setSalt(String salt) { this.salt = salt; }
    public String getIv() { return iv; }
    public void setIv(String iv) { this.iv = iv; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
