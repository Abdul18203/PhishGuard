
package com.phishing.detection.controller;

import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;

import com.phishing.detection.dto.AiPredictionResponse;
import com.phishing.detection.dto.ErrorResponse;
import com.phishing.detection.dto.ScanRequest;
import com.phishing.detection.dto.ScanResponse;
import com.phishing.detection.entity.ScanHistory;
import com.phishing.detection.entity.User;
import com.phishing.detection.repository.ScanHistoryRepository;
import com.phishing.detection.repository.UserRepository;
import com.phishing.detection.service.AiPredictionService;
import com.phishing.detection.service.UrlFeatureService;
import com.phishing.detection.service.UrlValidationService;

@RestController
@RequestMapping("/api/scan")
public class ScanController {

    private final UrlValidationService urlValidationService;
    private final UrlFeatureService urlFeatureService;
    private final ScanHistoryRepository scanHistoryRepository;
    private final UserRepository userRepository;
    private final AiPredictionService aiPredictionService;

    public ScanController(
            UrlValidationService urlValidationService,
            UrlFeatureService urlFeatureService,
            ScanHistoryRepository scanHistoryRepository,
            UserRepository userRepository,
            AiPredictionService aiPredictionService) {

        this.urlValidationService = urlValidationService;
        this.urlFeatureService = urlFeatureService;
        this.scanHistoryRepository = scanHistoryRepository;
        this.userRepository = userRepository;
        this.aiPredictionService = aiPredictionService;
    }

    @PostMapping
    public ResponseEntity<?> scanUrl(
            @RequestBody ScanRequest request) {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null
                || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof String email)) {

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(
                            "Please log in before scanning a URL."));
        }

        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(
                            "The authenticated user could not be found. Please log in again."));
        }

        if (request == null
                || !urlValidationService.isValidUrl(request.getUrl())) {

            return ResponseEntity
                    .badRequest()
                    .body(new ErrorResponse(
                            "Invalid URL. Please provide a valid HTTP or HTTPS URL."));
        }

        ScanResponse response =
                urlFeatureService.extractFeatures(request.getUrl());

        final AiPredictionResponse aiPrediction;

        try {
            aiPrediction =
                    aiPredictionService.predict(request.getUrl());

            if (aiPrediction == null
                    || aiPrediction.getPrediction() == null
                    || (!"PHISHING".equals(
                            aiPrediction.getPrediction())
                    && !"LEGITIMATE".equals(
                            aiPrediction.getPrediction()))) {

                return ResponseEntity
                        .status(HttpStatus.BAD_GATEWAY)
                        .body(new ErrorResponse(
                                "The AI service returned an invalid prediction."));
            }

        } catch (RestClientException ex) {
            return ResponseEntity
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(new ErrorResponse(
                            "The AI prediction service is unavailable. Please try again."));
        }

        ScanHistory history = new ScanHistory();

        history.setUser(user);
        history.setUrl(response.getUrl());
        history.setUrlLength(response.getUrlLength());
        history.setDotCount(response.getDotCount());
        history.setHyphenCount(response.getHyphenCount());

        history.setSpecialCharacterCount(
                response.getSpecialCharacterCount());

        history.setSubdomainCount(
                response.getSubdomainCount());

        history.setContainsAtSymbol(
                response.isContainsAtSymbol());

        history.setUsesIpAddress(
                response.isUsesIpAddress());

        history.setUsesHttps(
                response.isUsesHttps());

        history.setPrediction(
                aiPrediction.getPrediction());

        history.setPhishingScore(
                aiPrediction.getPhishingScore());

        history.setLegitimateScore(
                aiPrediction.getLegitimateScore());

        history.setModel(
                aiPrediction.getModel());

        history.setScannedAt(LocalDateTime.now());

        scanHistoryRepository.save(history);

        return ResponseEntity.ok(Map.of(
                "url", aiPrediction.getUrl(),
                "prediction", aiPrediction.getPrediction(),
                "phishingScore", aiPrediction.getPhishingScore(),
                "legitimateScore", aiPrediction.getLegitimateScore(),
                "model", aiPrediction.getModel(),
                "features", response
        ));
    }
}
