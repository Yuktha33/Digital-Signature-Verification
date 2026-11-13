package com.example.dsvs.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.dsvs.entity.VerificationLog;

public interface VerificationLogRepository extends JpaRepository<VerificationLog, Long> {
    List<VerificationLog> findAllByOrderByVerifiedAtDesc();
}
