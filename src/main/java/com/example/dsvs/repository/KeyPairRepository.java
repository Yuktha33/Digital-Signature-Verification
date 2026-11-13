package com.example.dsvs.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.dsvs.entity.KeyPairEntity;

public interface KeyPairRepository extends JpaRepository<KeyPairEntity, Long> {
    Optional<KeyPairEntity> findByAlias(String alias);
    boolean existsByAlias(String alias);
}
