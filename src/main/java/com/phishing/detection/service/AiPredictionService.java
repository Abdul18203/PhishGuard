package com.phishing.detection.service;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.phishing.detection.dto.AiPredictionResponse;

@Service
public class AiPredictionService {

    private static final Logger logger =
            LoggerFactory.getLogger(AiPredictionService.class);

    private final RestClient restClient;
    private final String aiServiceUrl;

    public AiPredictionService(
            @Value("${ai.service.url:http://127.0.0.1:5000}")
            String aiServiceUrl) {

        this.aiServiceUrl = aiServiceUrl;

        this.restClient = RestClient.builder()
                .baseUrl(aiServiceUrl)
                .build();

        logger.info("AI prediction service configured at: {}", aiServiceUrl);
    }

    public AiPredictionResponse predict(String url) {
        try {
            return restClient.post()
                    .uri("/predict")
                    .body(Map.of("url", url))
                    .retrieve()
                    .body(AiPredictionResponse.class);
        } catch (RestClientException ex) {
            logger.error(
                    "AI request to {} failed: {}: {}",
                    aiServiceUrl,
                    ex.getClass().getSimpleName(),
                    ex.getMessage(),
                    ex);
            throw ex;
        }
    }
}