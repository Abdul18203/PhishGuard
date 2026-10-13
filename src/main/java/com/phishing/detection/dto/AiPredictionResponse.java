package com.phishing.detection.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AiPredictionResponse {

    private String url;
    private String prediction;
    private double phishingScore;
    private double legitimateScore;
    private String model;

    public AiPredictionResponse() {
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getPrediction() {
        return prediction;
    }

    public void setPrediction(String prediction) {
        this.prediction = prediction;
    }

    public double getPhishingScore() {
        return phishingScore;
    }

    public void setPhishingScore(double phishingScore) {
        this.phishingScore = phishingScore;
    }

    public double getLegitimateScore() {
        return legitimateScore;
    }

    public void setLegitimateScore(double legitimateScore) {
        this.legitimateScore = legitimateScore;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }
}