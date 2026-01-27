// Ollama Integration for Local AI Model Inference
// Provides vulnerability analysis using locally-hosted LLMs

use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::Duration;

const OLLAMA_API_URL: &str = "http://localhost:11434";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaModel {
    pub name: String,
    pub size: u64,
    pub digest: String,
    pub modified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaStatus {
    pub available: bool,
    pub version: Option<String>,
    pub models: Vec<OllamaModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GenerateRequest {
    model: String,
    prompt: String,
    stream: bool,
    options: Option<GenerateOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GenerateOptions {
    temperature: f32,
    top_p: f32,
    top_k: i32,
    num_predict: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GenerateResponse {
    model: String,
    created_at: String,
    response: String,
    done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListModelsResponse {
    models: Vec<OllamaModel>,
}

pub struct OllamaClient {
    client: Client,
    base_url: String,
}

impl OllamaClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(300)) // 5 minutes for large models
                .build()
                .unwrap(),
            base_url: OLLAMA_API_URL.to_string(),
        }
    }

    /// Check if Ollama is available and running
    pub async fn check_status(&self) -> OllamaStatus {
        // Try to connect to Ollama
        match self.client.get(&format!("{}/api/tags", self.base_url))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    // Parse models list
                    match response.json::<ListModelsResponse>().await {
                        Ok(models_response) => OllamaStatus {
                            available: true,
                            version: Some("1.0".to_string()), // Ollama doesn't expose version via API
                            models: models_response.models,
                        },
                        Err(_) => OllamaStatus {
                            available: true,
                            version: Some("1.0".to_string()),
                            models: vec![],
                        },
                    }
                } else {
                    OllamaStatus {
                        available: false,
                        version: None,
                        models: vec![],
                    }
                }
            }
            Err(_) => OllamaStatus {
                available: false,
                version: None,
                models: vec![],
            },
        }
    }

    /// List available models
    pub async fn list_models(&self) -> Result<Vec<OllamaModel>, String> {
        let response = self.client
            .get(&format!("{}/api/tags", self.base_url))
            .send()
            .await
            .map_err(|e| format!("Failed to connect to Ollama: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Ollama returned error: {}", response.status()));
        }

        let models_response: ListModelsResponse = response.json().await
            .map_err(|e| format!("Failed to parse models response: {}", e))?;

        Ok(models_response.models)
    }

    /// Check if a specific model is available
    pub async fn is_model_available(&self, model_name: &str) -> bool {
        match self.list_models().await {
            Ok(models) => models.iter().any(|m| m.name.starts_with(model_name)),
            Err(_) => false,
        }
    }

    /// Pull a model from Ollama registry (async, may take a while)
    pub async fn pull_model(&self, model_name: &str) -> Result<(), String> {
        let request = serde_json::json!({
            "name": model_name,
            "stream": false
        });

        let response = self.client
            .post(&format!("{}/api/pull", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Failed to pull model: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to pull model: {}", response.status()))
        }
    }

    /// Generate text using a specific model
    pub async fn generate(&self, model: &str, prompt: &str) -> Result<String, String> {
        let request = GenerateRequest {
            model: model.to_string(),
            prompt: prompt.to_string(),
            stream: false,
            options: Some(GenerateOptions {
                temperature: 0.7,
                top_p: 0.9,
                top_k: 40,
                num_predict: 2048,
            }),
        };

        let response = self.client
            .post(&format!("{}/api/generate", self.base_url))
            .json(&request)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| format!("Failed to generate response: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Ollama returned error: {}", response.status()));
        }

        let generate_response: GenerateResponse = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(generate_response.response)
    }

    /// Analyze a vulnerability using the model
    pub async fn analyze_vulnerability(
        &self,
        model: &str,
        cve_id: &str,
        package_name: &str,
        package_version: &str,
        severity: &str,
        summary: &str,
        question: &str,
    ) -> Result<String, String> {
        let prompt = format!(
            r#"You are a cybersecurity expert analyzing vulnerabilities.

CVE ID: {}
Package: {} version {}
Severity: {}
Description: {}

User Question: {}

Please provide a clear, concise, and helpful response. Format your response in a conversational, easy-to-understand way:

1. Explain the vulnerability in plain language
2. Describe the real-world impact and risk
3. Provide practical, actionable advice
4. Be specific about severity and urgency

Use formatting to make your response easy to read:
- Use **bold** for important terms (surround with **)
- Use bullet points (starting with "-") for lists
- Break information into short paragraphs
- Avoid overly technical jargon unless necessary

Keep your response focused and relevant to the user's specific question."#,
            cve_id, package_name, package_version, severity, summary, question
        );

        self.generate(model, &prompt).await
    }

    /// Quick test to verify model works
    pub async fn test_model(&self, model: &str) -> Result<bool, String> {
        let test_prompt = "Respond with 'OK' if you can understand this message.";
        match self.generate(model, test_prompt).await {
            Ok(response) => {
                // Check if response contains something reasonable
                Ok(!response.trim().is_empty())
            }
            Err(e) => Err(e),
        }
    }
}

impl Default for OllamaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ollama_connection() {
        let client = OllamaClient::new();
        let status = client.check_status().await;
        println!("Ollama status: {:#?}", status);

        if status.available {
            println!("Available models:");
            for model in &status.models {
                println!("  - {}", model.name);
            }
        }
    }

    #[tokio::test]
    async fn test_model_list() {
        let client = OllamaClient::new();
        match client.list_models().await {
            Ok(models) => {
                println!("Found {} models", models.len());
                for model in models {
                    println!("  - {} ({})", model.name, model.digest);
                }
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}
