
package com.phishing.detection.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.phishing.detection.entity.ScanHistory;

@Repository
public interface ScanHistoryRepository
        extends JpaRepository<ScanHistory, Long> {

    List<ScanHistory> findAllByOrderByScannedAtDesc();

    Page<ScanHistory> findByUser_Email(
            String email,
            Pageable pageable
    );

    long countByUser_Email(String email);

    @Query("""
            SELECT COUNT(s)
            FROM ScanHistory s
            WHERE s.user.email = :email
              AND LOWER(TRIM(s.prediction)) = 'phishing'
            """)
    long countPhishingByUserEmail(
            @Param("email") String email
    );

    @Query("""
            SELECT COUNT(s)
            FROM ScanHistory s
            WHERE s.user.email = :email
              AND LOWER(TRIM(s.prediction)) = 'legitimate'
            """)
    long countLegitimateByUserEmail(
            @Param("email") String email
    );
}
