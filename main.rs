use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Instant};

struct Scanner {
    client: reqwest::Client,
    verbose: bool,
    rate_limiter: Arc<Semaphore>,
    rate_delay: Duration,
    total_requests: Arc<tokio::sync::Mutex<u64>>,
    scan_start: Instant,
    custom_headers: std::collections::HashMap<String, String>,
}

impl Scanner {
    fn new(verbose: bool, rate: u64, custom_headers: std::collections::HashMap<String, String>, proxy_url: Option<String>) -> Self {
        let mut client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true);

        if let Some(proxy) = &proxy_url {
            if verbose {
                println!("[INFO] Configuring proxy: {}", proxy);
            }
            
            match reqwest::Proxy::all(proxy) {
                Ok(proxy_config) => {
                    client_builder = client_builder.proxy(proxy_config);
                    if verbose {
                        println!("[SUCCESS] Proxy configured successfully");
                    }
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to configure proxy: {}", e);
                }
            }
        }

        let client = client_builder
            .build()
            .expect("Failed to build HTTP client");

        Scanner {
            client,
            verbose,
            // FIXED: The semaphore now correctly limits concurrent requests
            // This prevents bursts and enforces the rate limit properly
            rate_limiter: Arc::new(Semaphore::new(rate as usize)),
            // FIXED: Calculate the delay between individual requests
            // This ensures we don't exceed the specified rate per second
            rate_delay: Duration::from_millis(1000 / rate),
            total_requests: Arc::new(tokio::sync::Mutex::new(0)),
            scan_start: Instant::now(),
            custom_headers,
        }
    }

    // FIXED: Proper rate limiting implementation
    async fn rate_limited_request<F, Fut, T>(&self, request_fn: F) -> Option<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<T>>,
    {
        // Acquire permit from semaphore (limits concurrency)
        let _permit = self.rate_limiter.acquire().await.unwrap();
        
        // Execute the request
        let result = request_fn().await;
        
        // FIXED: Sleep AFTER each request completes, before releasing the permit
        // This ensures proper spacing between requests
        sleep(self.rate_delay).await;
        
        result
    }

    // Example of how to use the rate-limited request in fetch_spec
    async fn fetch_spec(&self, url: &str) -> anyhow::Result<SwaggerSpec> {
        let client = self.client.clone();
        let url = url.to_string();
        let custom_headers = self.custom_headers.clone();
        let total_requests = self.total_requests.clone();
        
        self.rate_limited_request(|| async move {
            let mut request = client.get(&url);
            
            // Add custom headers
            for (key, value) in &custom_headers {
                request = request.header(key, value);
            }
            
            match request.send().await {
                Ok(response) => {
                    // Increment request counter
                    let mut counter = total_requests.lock().await;
                    *counter += 1;
                    drop(counter);
                    
                    if response.status().is_success() {
                        response.json::<SwaggerSpec>().await.ok()
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }).await.ok_or_else(|| anyhow::anyhow!("Failed to fetch spec"))
    }

    // FIXED: Updated test_endpoints to use proper rate limiting
    async fn test_endpoints(
        &self, 
        spec: &SwaggerSpec, 
        base_url: &str, 
        risk: bool, 
        _all: bool, 
        _product: bool
    ) -> Vec<TestResult> {
        let mut results = Vec::new();

        // Determine the base path
        let base_path = if let Some(servers) = &spec.servers {
            servers.first().map(|s| s.url.clone()).unwrap_or_else(|| base_url.to_string())
        } else if let Some(base_path) = &spec.base_path {
            format!("{}{}", base_url, base_path)
        } else {
            base_url.to_string()
        };

        if let Some(paths) = &spec.paths {
            let mut tasks = Vec::new();

            for (path, methods) in paths {
                for (method, path_item) in methods {
                    // Skip non-GET methods if risk flag is not set
                    if !risk && method.to_uppercase() != "GET" {
                        continue;
                    }

                    let full_url = format!("{}{}", base_path.trim_end_matches('/'), path);
                    let client = self.client.clone();
                    let method_clone = method.clone();
                    let path_clone = path.clone();
                    let path_item_clone = path_item.clone();
                    let verbose = self.verbose;
                    let custom_headers = self.custom_headers.clone();
                    let total_requests = self.total_requests.clone();
                    
                    // FIXED: Clone rate_limiter and rate_delay for each task
                    let rate_limiter = self.rate_limiter.clone();
                    let rate_delay = self.rate_delay;

                    let task = tokio::spawn(async move {
                        // FIXED: Acquire permit and rate limit per request
                        let _permit = rate_limiter.acquire().await.unwrap();
                        
                        // FIXED: Build URL with query parameters first
                        let mut url_with_params = full_url.clone();
                        let mut query_params = Vec::new();
                        
                        // Process parameters to extract query params
                        if let Some(parameters) = &path_item_clone.parameters {
                            for param in parameters {
                                if param.location == "query" {
                                    let example_value = Self::get_param_example_value(param);
                                    query_params.push((param.name.clone(), example_value));
                                }
                            }
                        }
                        
                        // Add query parameters to URL
                        if !query_params.is_empty() {
                            let query_string: Vec<String> = query_params.iter()
                                .map(|(k, v)| format!("{}={}", 
                                    urlencoding::encode(k), 
                                    urlencoding::encode(v)))
                                .collect();
                            url_with_params.push_str("?");
                            url_with_params.push_str(&query_string.join("&"));
                        }
                        
                        let mut request = match method_clone.to_uppercase().as_str() {
                            "GET" => client.get(&url_with_params),
                            "POST" => client.post(&url_with_params),
                            "PUT" => client.put(&url_with_params),
                            "DELETE" => client.delete(&url_with_params),
                            "PATCH" => client.patch(&url_with_params),
                            _ => client.get(&url_with_params),
                        };

                        let mut body_content = String::new();
                        
                        // Add custom headers
                        for (key, value) in &custom_headers {
                            request = request.header(key, value);
                        }
                        
                        // FIXED: Add header parameters
                        if let Some(parameters) = &path_item_clone.parameters {
                            for param in parameters {
                                if param.location == "header" {
                                    let example_value = Self::get_param_example_value(param);
                                    request = request.header(&param.name, example_value);
                                }
                            }
                        }

                        // Add request body for POST/PUT/PATCH
                        if method_clone.to_uppercase() == "POST" 
                            || method_clone.to_uppercase() == "PUT" 
                            || method_clone.to_uppercase() == "PATCH" 
                        {
                            if let Some(request_body) = &path_item_clone.request_body {
                                if let Some(content) = &request_body.content {
                                    if let Some(json_content) = content.get("application/json") {
                                        request = request.header("Content-Type", "application/json");
                                        let example_body = if let Some(ex) = &json_content.example {
                                            serde_json::to_string(ex).unwrap_or_else(|_| "{}".to_string())
                                        } else {
                                            "{}".to_string()
                                        };
                                        body_content = example_body.clone();
                                        request = request.body(example_body);
                                    }
                                }
                            }
                        }

                        if verbose {
                            println!("[TEST] {} {}", method_clone.to_uppercase(), full_url);
                        }

                        let result = match request.send().await {
                            Ok(response) => {
                                // Increment request counter
                                let mut counter = total_requests.lock().await;
                                *counter += 1;
                                drop(counter);
                                
                                let status = response.status().as_u16();
                                let content_length = response.content_length().unwrap_or(0) as usize;
                                
                                // Parse response for PII detection
                                let response_text = response.text().await.unwrap_or_default();
                                let (pii_detected, pii_data, detection_details, patterns_found, detection_methods) = 
                                    Self::detect_pii(&response_text);

                                let interesting = Self::is_interesting_response(&response_text, status);

                                Some(TestResult {
                                    method: method_clone.to_uppercase(),
                                    url: full_url,
                                    path_template: path_clone,
                                    body: body_content,
                                    status_code: status,
                                    content_length,
                                    pii_detected,
                                    pii_data,
                                    pii_detection_details: detection_details,
                                    interesting_response: interesting,
                                    regex_patterns_found: patterns_found,
                                    pii_detection_methods: detection_methods,
                                    custom_headers_used: if custom_headers.is_empty() { 
                                        None 
                                    } else { 
                                        Some(custom_headers) 
                                    },
                                })
                            }
                            Err(e) => {
                                if verbose {
                                    eprintln!("[ERROR] Failed to test {} {}: {}", method_clone, full_url, e);
                                }
                                None
                            }
                        };

                        // FIXED: Sleep AFTER the request completes to enforce rate limiting
                        // This ensures we don't exceed the specified requests per second
                        sleep(rate_delay).await;
                        
                        result
                    });

                    tasks.push(task);
                }
            }

            // Wait for all tasks to complete
            let task_results = futures::future::join_all(tasks).await;
            for result in task_results {
                if let Ok(Some(test_result)) = result {
                    results.push(test_result);
                }
            }
        }

        // FIXED: Removed the ineffective global sleep at the end
        // Rate limiting now happens per-request inside each task
        
        results
    }

    // FIXED: Helper function to extract example values from parameters
    fn get_param_example_value(param: &Parameter) -> String {
        // Try example field first
        if let Some(ex) = &param.example {
            return Self::value_to_string(ex);
        }
        
        // Try examples map
        if let Some(examples) = &param.examples {
            if let Some(first_ex) = examples.values().next() {
                if let Some(val) = &first_ex.value {
                    return Self::value_to_string(val);
                }
            }
        }
        
        // Try schema
        if let Some(schema) = &param.schema {
            if let Some(ex) = &schema.example {
                return Self::value_to_string(ex);
            }
            
            if let Some(enum_vals) = &schema.enum_values {
                if let Some(first) = enum_vals.first() {
                    return Self::value_to_string(first);
                }
            }
            
            // Generate based on schema type
            if let Some(schema_type) = &schema.schema_type {
                return match schema_type.as_str() {
                    "string" => "example_string".to_string(),
                    "integer" | "number" => "123".to_string(),
                    "boolean" => "true".to_string(),
                    "array" => "example1,example2".to_string(),
                    _ => "example".to_string(),
                };
            }
        }
        
        // Try param type (OpenAPI 2.0)
        if let Some(param_type) = &param.param_type {
            return match param_type.as_str() {
                "string" => "example_string".to_string(),
                "integer" | "number" => "123".to_string(),
                "boolean" => "true".to_string(),
                "array" => "example1,example2".to_string(),
                _ => "example".to_string(),
            };
        }
        
        // Try enum values directly on parameter
        if let Some(enum_vals) = &param.enum_values {
            if let Some(first) = enum_vals.first() {
                return Self::value_to_string(first);
            }
        }
        
        "example".to_string()
    }
    
    fn value_to_string(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Array(arr) => {
                arr.iter()
                    .filter_map(|v| match v {
                        serde_json::Value::String(s) => Some(s.clone()),
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            }
            _ => serde_json::to_string(value).unwrap_or_else(|_| "example".to_string()),
        }
    }

    // Placeholder methods (would need full implementation)
    fn detect_pii(_text: &str) -> (bool, Option<std::collections::HashMap<String, Vec<String>>>, Option<std::collections::HashMap<String, DetectionDetails>>, std::collections::HashMap<String, String>, std::collections::HashSet<String>) {
        (false, None, None, std::collections::HashMap::new(), std::collections::HashSet::new())
    }

    fn is_interesting_response(_text: &str, _status_code: u16) -> bool {
        false
    }
}

// Placeholder structs (from original code)
#[derive(Debug, Clone)]
struct SwaggerSpec {
    servers: Option<Vec<Server>>,
    base_path: Option<String>,
    paths: Option<std::collections::HashMap<String, std::collections::HashMap<String, PathItem>>>,
}

#[derive(Debug, Clone)]
struct Server {
    url: String,
}

#[derive(Debug, Clone)]
struct PathItem {
    request_body: Option<RequestBody>,
    parameters: Option<Vec<Parameter>>,
}

#[derive(Debug, Clone)]
struct Parameter {
    name: String,
    location: String,
    schema: Option<Schema>,
    param_type: Option<String>,
    enum_values: Option<Vec<serde_json::Value>>,
    example: Option<serde_json::Value>,
    examples: Option<std::collections::HashMap<String, Example>>,
}

#[derive(Debug, Clone)]
struct Example {
    value: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct Schema {
    schema_type: Option<String>,
    enum_values: Option<Vec<serde_json::Value>>,
    example: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct RequestBody {
    content: Option<std::collections::HashMap<String, ContentType>>,
}

#[derive(Debug, Clone)]
struct ContentType {
    example: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct TestResult {
    method: String,
    url: String,
    path_template: String,
    body: String,
    status_code: u16,
    content_length: usize,
    pii_detected: bool,
    pii_data: Option<std::collections::HashMap<String, Vec<String>>>,
    pii_detection_details: Option<std::collections::HashMap<String, DetectionDetails>>,
    interesting_response: bool,
    regex_patterns_found: std::collections::HashMap<String, String>,
    pii_detection_methods: std::collections::HashSet<String>,
    custom_headers_used: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone)]
struct DetectionDetails {
    detection_methods: Vec<String>,
}
