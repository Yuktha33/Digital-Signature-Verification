package com.example.dsvs.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.dsvs.entity.SignatureRecord;

public interface SignatureRecordRepository extends JpaRepository<SignatureRecord, Long> {
    List<SignatureRecord> findAllByOrderByCreatedAtDesc();
}
