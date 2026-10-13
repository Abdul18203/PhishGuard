package com.phishing.detection.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.phishing.detection.dto.AiPredictionResponse;

@Service
public class AiPredictionService {

    private final RestClient restClient;

    public AiPredictionService(
            @Value("${ai.service.url:http://127.0.0.1:5000}")
            String aiServiceUrl) {

        this.restClient = RestClient.builder()
                .baseUrl(aiServiceUrl)
                .build();
    }

    public AiPredictionResponse predict(String url) {
        return restClient.post()
                .uri("/predict")
                .body(Map.of("url", url))
                .retrieve()
                .body(AiPredictionResponse.class);
    }
}