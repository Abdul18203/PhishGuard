
package com.phishing.detection.controller;

import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.phishing.detection.entity.ScanHistory;
import com.phishing.detection.repository.ScanHistoryRepository;

@RestController
@RequestMapping("/api/scan/history")
public class ScanHistoryController {

    private final ScanHistoryRepository scanHistoryRepository;

    public ScanHistoryController(
            ScanHistoryRepository scanHistoryRepository) {

        this.scanHistoryRepository = scanHistoryRepository;
    }

    @GetMapping
    public ResponseEntity<?> getScanHistory(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        if (page < 0 || size < 1 || size > 100) {
            return ResponseEntity.badRequest().build();
        }

        String email = getAuthenticatedEmail();

        if (email == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .build();
        }

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(
                        Sort.Direction.DESC,
                        "scannedAt"
                )
        );

        Page<ScanHistory> history =
                scanHistoryRepository.findByUser_Email(
                        email,
                        pageable
                );

        return ResponseEntity.ok(history);
    }

    @GetMapping("/stats")
    public ResponseEntity<?> getScanStatistics() {

        String email = getAuthenticatedEmail();

        if (email == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .build();
        }

        long totalScans =
                scanHistoryRepository.countByUser_Email(email);

        long phishingDetected =
                scanHistoryRepository.countPhishingByUserEmail(email);

        long legitimateUrls =
                scanHistoryRepository.countLegitimateByUserEmail(email);

        long classifiedScans =
                phishingDetected + legitimateUrls;

        double detectionRate = classifiedScans == 0
                ? 0.0
                : (phishingDetected * 100.0) / classifiedScans;

        Map<String, Object> statistics = Map.of(
                "totalScans", totalScans,
                "phishingDetected", phishingDetected,
                "legitimateUrls", legitimateUrls,
                "classifiedScans", classifiedScans,
                "detectionRate", Math.round(detectionRate * 100.0) / 100.0
        );

        return ResponseEntity.ok(statistics);
    }

    private String getAuthenticatedEmail() {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null
                || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof String email)) {

            return null;
        }

        return email;
    }
}
