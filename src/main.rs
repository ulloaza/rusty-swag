use clap::Parser;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;
use url::Url;
use anyhow::{anyhow, Result};
use futures::future::join_all;
use std::fs;
use std::path::Path;
use std::io::Write;
use chrono::Local;

#[derive(Parser)]
#[command(name = "rusty-swag")]
#[command(about = "Rusty-Swag: Identify, Parse, and quickly scan Swagger API and OpenAPI docs")]
struct Args {
    /// Base URL(s) or spec URL(s) of the target API(s)
    urls: Vec<String>,
    
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Include non-GET requests in testing
    #[arg(long)]
    risk: bool,
    
    /// Include all HTTP status codes in the results, excluding 401 and 403
    #[arg(long)]
    all: bool,
    
    /// Output all endpoints in JSON, flagging those that contain PII or have large responses
    #[arg(long)]
    product: bool,
    
    /// Display scan statistics
    #[arg(long)]
    stats: bool,
    
    /// Set the rate limit in requests per second (default: 30, minimum: 1)
    #[arg(long, default_value = "30")]
    rate: u64,
    
    /// Output results in JSON format in default mode
    #[arg(long)]
    json: bool,
    
    /// Generate sample HTTP requests for discovered endpoints and save each to individual text files
    #[arg(long)]
    samples: bool,
    
    /// Add custom headers to API endpoint tests (format: "Header-Name: Header-Value")
    /// Can be specified multiple times for multiple headers
    /// Example: --header "Authorization: Bearer token123" --header "X-API-Key: mykey"
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    headers: Vec<String>,
    
    /// Route all requests through a proxy server
    /// Supports HTTP, HTTPS, and SOCKS5 proxies
    /// Examples: --proxy "http://127.0.0.1:8080" or --proxy "socks5://127.0.0.1:1080"
    #[arg(long, value_name = "PROXY_URL")]
    proxy: Option<String>,
    
    /// Directory to save individual HTTP request files (default: "swagger-samples")
    #[arg(long, default_value = "swagger-samples")]
    samples_dir: String,

    /// Enable brute force testing of parameters with common values
    /// Tests URL query parameters and POST body fields with multiple payloads
    #[arg(short = 'b', long)]
    brute: bool,

    /// Custom wordlist file for brute force testing (one value per line)
    /// If not specified, uses built-in common test values
    #[arg(long, value_name = "FILE")]
    wordlist: Option<String>,

    /// Maximum number of brute force combinations per endpoint (default: 100)
    /// Helps prevent excessive requests on endpoints with many parameters
    #[arg(long, default_value = "100")]
    brute_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SwaggerSpec {
    swagger: Option<String>,
    openapi: Option<String>,
    info: Option<Value>,
    servers: Option<Vec<Server>>,
    #[serde(rename = "basePath")]
    base_path: Option<String>,
    paths: Option<HashMap<String, HashMap<String, PathItem>>>,
    components: Option<Components>,
    definitions: Option<HashMap<String, Schema>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Components {
    schemas: Option<HashMap<String, Schema>>,
    examples: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Server {
    url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PathItem {
    parameters: Option<Vec<Parameter>>,
    #[serde(rename = "requestBody")]
    request_body: Option<RequestBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Parameter {
    name: String,
    #[serde(rename = "in")]
    location: String,
    schema: Option<Schema>,
    #[serde(rename = "type")]
    param_type: Option<String>,
    #[serde(rename = "enum")]
    enum_values: Option<Vec<Value>>,
    example: Option<Value>,
    examples: Option<HashMap<String, Example>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Example {
    value: Option<Value>,
    #[serde(rename = "externalValue")]
    external_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestBody {
    content: Option<HashMap<String, ContentType>>,
    required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContentType {
    schema: Option<Schema>,
    example: Option<Value>,
    examples: Option<HashMap<String, Example>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Schema {
    #[serde(rename = "type")]
    schema_type: Option<String>,
    properties: Option<HashMap<String, Schema>>,
    items: Option<Box<Schema>>,
    #[serde(rename = "enum")]
    enum_values: Option<Vec<Value>>,
    #[serde(rename = "oneOf")]
    one_of: Option<Vec<Schema>>,
    #[serde(rename = "anyOf")]
    any_of: Option<Vec<Schema>>,
    #[serde(rename = "allOf")]
    all_of: Option<Vec<Schema>>,
    example: Option<Value>,
    examples: Option<Vec<Value>>,
    #[serde(rename = "$ref")]
    reference: Option<String>,
    required: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct TestResult {
    method: String,
    url: String,
    path_template: String,
    body: String,
    status_code: u16,
    content_length: usize,
    pii_detected: bool,
    pii_data: Option<HashMap<String, Vec<String>>>,
    pii_detection_details: Option<HashMap<String, DetectionDetails>>,
    interesting_response: bool,
    regex_patterns_found: HashMap<String, String>,
    pii_detection_methods: HashSet<String>,
    custom_headers_used: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
struct SampleRequest {
    method: String,
    url: String,
    path: String,
    headers: HashMap<String, String>,
    query_params: Option<HashMap<String, String>>,
    body: Option<String>,
    description: Option<String>,
    curl_command: String,
}

#[derive(Debug, Clone, Serialize)]
struct DetectionDetails {
    detection_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ScanStats {
    unique_hosts_provided: usize,
    active_hosts: usize,
    hosts_with_valid_spec: usize,
    hosts_with_valid_endpoint: usize,
    hosts_with_pii: usize,
    pii_detection_methods: Vec<String>,
    percentage_hosts_with_endpoint: f64,
    regexes_found: Vec<String>,
    total_requests_sent: u64,
    average_requests_per_second: f64,
    custom_headers_count: usize,
    proxy_used: bool,
}

#[derive(Debug, Clone)]
struct BruteConfig {
    enabled: bool,
    values: Vec<String>,
    limit: usize,
}

impl BruteConfig {
    fn new(enabled: bool, wordlist_path: Option<String>, limit: usize) -> Self {
        let values = if enabled {
            if let Some(path) = wordlist_path {
                // Load wordlist from file
                match fs::read_to_string(&path) {
                    Ok(content) => content.lines()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty() && !s.starts_with('#'))
                        .collect(),
                    Err(e) => {
                        eprintln!("[WARN] Failed to load wordlist {}: {}, using defaults", path, e);
                        Self::default_values()
                    }
                }
            } else {
                Self::default_values()
            }
        } else {
            Vec::new()
        };

        BruteConfig { enabled, values, limit }
    }

    fn default_values() -> Vec<String> {
        vec![
            // Common IDs
            "1".to_string(),
            "0".to_string(),
            "-1".to_string(),
            "2".to_string(),
            "100".to_string(),
            "999".to_string(),
            "9999".to_string(),
            // Common strings
            "admin".to_string(),
            "test".to_string(),
            "user".to_string(),
            "guest".to_string(),
            "root".to_string(),
            "null".to_string(),
            "undefined".to_string(),
            // SQL injection probes
            "'".to_string(),
            "\"".to_string(),
            "1'--".to_string(),
            "1 OR 1=1".to_string(),
            "' OR '1'='1".to_string(),
            // Path traversal
            "../".to_string(),
            "..%2f".to_string(),
            "....//....//".to_string(),
            // XSS probes
            "<script>alert(1)</script>".to_string(),
            "<img src=x onerror=alert(1)>".to_string(),
            "javascript:alert(1)".to_string(),
            // SSTI probes
            "{{7*7}}".to_string(),
            "${7*7}".to_string(),
            "<%= 7*7 %>".to_string(),
            // Command injection
            "; ls".to_string(),
            "| cat /etc/passwd".to_string(),
            "`id`".to_string(),
            "$(id)".to_string(),
            // Boolean values
            "true".to_string(),
            "false".to_string(),
            // Empty/special
            "".to_string(),
            " ".to_string(),
            "%00".to_string(),
            "%0a".to_string(),
            // UUIDs
            "00000000-0000-0000-0000-000000000000".to_string(),
            // Large numbers
            "999999999999".to_string(),
            "-999999999999".to_string(),
        ]
    }

    fn get_values_for_type(&self, param_type: Option<&str>) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        match param_type {
            Some("integer") | Some("number") => {
                self.values.iter()
                    .filter(|v| v.parse::<i64>().is_ok() || v.contains("'") || v.contains("OR"))
                    .cloned()
                    .collect()
            }
            Some("boolean") => vec![
                "true".to_string(),
                "false".to_string(),
                "1".to_string(),
                "0".to_string(),
                "yes".to_string(),
                "no".to_string(),
            ],
            _ => self.values.clone(),
        }
    }
}

/// Type alias for query parameter combinations used in brute forcing
type QueryParamCombos = Vec<(String, String)>;

/// Type alias for brute force test combinations (query params, optional body)
type BruteCombination = (QueryParamCombos, Option<Value>);

/// Type alias for PII detection results
type PiiDetectionResult = (
    bool,
    Option<HashMap<String, Vec<String>>>,
    Option<HashMap<String, DetectionDetails>>,
    HashMap<String, String>,
    HashSet<String>,
);

struct Scanner {
    client: Client,
    verbose: bool,
    rate_limiter: Arc<Semaphore>,
    rate_delay: Duration,
    total_requests: Arc<Mutex<u64>>,
    scan_start: Instant,
    custom_headers: HashMap<String, String>,
    brute_config: BruteConfig,
}

impl Scanner {
    fn new(verbose: bool, rate: u64, custom_headers: HashMap<String, String>, proxy_url: Option<String>, brute_config: BruteConfig) -> Self {
        // Ensure rate is at least 1 to avoid division by zero
        let rate = rate.max(1);

        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true);

        // Configure proxy if provided
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

        if brute_config.enabled && verbose {
            println!("[INFO] Brute force mode enabled with {} test values (limit: {} per endpoint)",
                brute_config.values.len(), brute_config.limit);
        }

        Scanner {
            client,
            verbose,
            rate_limiter: Arc::new(Semaphore::new(rate as usize)),
            rate_delay: Duration::from_millis(1000 / rate),
            total_requests: Arc::new(Mutex::new(0)),
            scan_start: Instant::now(),
            custom_headers,
            brute_config,
        }
    }

    async fn process_url(&self, url: &str, risk: bool, all: bool, product: bool, samples: bool) -> (Vec<TestResult>, bool, Option<Vec<SampleRequest>>) {
        let mut results = Vec::new();
        let mut found_spec = false;
        let mut sample_requests = if samples {
            Some(Vec::new())
        } else {
            None
        };

        // Parse URL first to validate it
        let parsed_url = match self.parse_url(url) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("[ERROR] Invalid URL {}: {}", url, e);
                return (results, found_spec, sample_requests);
            }
        };

        let full_url = parsed_url.to_string();
        let base_url = match self.normalize_url(url) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("[ERROR] Invalid URL {}: {}", url, e);
                return (results, found_spec, sample_requests);
            }
        };

        if self.verbose {
            println!("\n[INFO] Processing: {}", full_url);
        }

        // Helper closure to process a found spec
        let process_spec = |spec: &SwaggerSpec, spec_url: &str, base: &str,
                           sample_requests: &mut Option<Vec<SampleRequest>>| {
            if !product {
                println!("[SUCCESS] Found spec at: {}", spec_url);
            }

            // Generate sample requests if flag is set
            if samples {
                if let Some(ref mut requests) = sample_requests {
                    let new_samples = self.generate_samples(spec, base, risk);
                    requests.extend(new_samples);
                }
            }
        };

        // If URL looks like a direct spec URL, try it first
        if self.is_direct_spec_url(&full_url) {
            if self.verbose {
                println!("[INFO] URL appears to be a direct spec link, trying it first...");
            }

            if let Ok(spec) = self.fetch_spec(&full_url).await {
                found_spec = true;
                process_spec(&spec, &full_url, &base_url, &mut sample_requests);

                // Test endpoints
                let endpoint_results = self.test_endpoints(&spec, &base_url, risk, all, product).await;
                results.extend(endpoint_results);

                return (results, found_spec, sample_requests);
            } else if self.verbose {
                println!("[INFO] Direct spec URL failed, falling back to discovery...");
            }
        }

        // Try to find and fetch the Swagger/OpenAPI spec from common locations
        let spec_locations = self.get_spec_locations(&base_url);

        for spec_url in spec_locations {
            if let Ok(spec) = self.fetch_spec(&spec_url).await {
                found_spec = true;
                process_spec(&spec, &spec_url, &base_url, &mut sample_requests);

                // Test endpoints
                let endpoint_results = self.test_endpoints(&spec, &base_url, risk, all, product).await;
                results.extend(endpoint_results);
                break;
            }
        }

        if !found_spec && self.verbose {
            println!("[WARN] No Swagger/OpenAPI spec found for: {}", base_url);
        }

        (results, found_spec, sample_requests)
    }

    fn normalize_url(&self, url: &str) -> Result<String> {
        let mut parsed = if url.starts_with("http://") || url.starts_with("https://") {
            Url::parse(url)?
        } else {
            Url::parse(&format!("https://{}", url))?
        };

        // Remove path if present to get base URL
        parsed.set_path("");
        parsed.set_query(None);
        parsed.set_fragment(None);

        Ok(parsed.to_string().trim_end_matches('/').to_string())
    }

    /// Check if a URL appears to be a direct link to a spec file
    fn is_direct_spec_url(&self, url: &str) -> bool {
        let lower = url.to_lowercase();
        // Check for common spec file extensions and paths
        lower.ends_with(".json")
            || lower.ends_with(".yaml")
            || lower.ends_with(".yml")
            || lower.contains("/swagger.json")
            || lower.contains("/openapi.json")
            || lower.contains("/api-docs")
            || lower.contains("/swagger.yaml")
            || lower.contains("/openapi.yaml")
    }

    /// Parse a URL, adding scheme if missing
    fn parse_url(&self, url: &str) -> Result<Url> {
        if url.starts_with("http://") || url.starts_with("https://") {
            Ok(Url::parse(url)?)
        } else {
            Ok(Url::parse(&format!("https://{}", url))?)
        }
    }

    fn get_spec_locations(&self, base_url: &str) -> Vec<String> {
        let common_paths = vec![
            "/swagger.json",
            "/api/swagger.json",
            "/swagger/v1/swagger.json",
            "/api-docs",
            "/api/api-docs",
            "/openapi.json",
            "/api/openapi.json",
            "/openapi/v1/openapi.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api/v1/documentation",
            "/api/v1/swagger.json",
            "/api/v2/swagger.json",
            "/api/v3/swagger.json",
            "/api/v1/openapi.json",
            "/api/v2/openapi.json",
            "/api/v3/openapi.json",
            "/docs/api",
            "/swagger-ui/swagger.json",
            "/api/swagger-ui/swagger.json",
        ];

        common_paths.iter()
            .map(|path| format!("{}{}", base_url, path))
            .collect()
    }

    async fn fetch_spec(&self, url: &str) -> Result<SwaggerSpec> {
        let _permit = self.rate_limiter.acquire().await?;
        
        let mut request = self.client.get(url);
        
        // Add custom headers
        for (key, value) in &self.custom_headers {
            request = request.header(key, value);
        }
        
        let response = request.send().await?;
        
        // Increment request counter
        let mut counter = self.total_requests.lock().await;
        *counter += 1;
        
        if response.status().is_success() {
            let spec: SwaggerSpec = response.json().await?;
            Ok(spec)
        } else {
            Err(anyhow!("Failed to fetch spec: HTTP {}", response.status()))
        }
    }

    fn generate_samples(&self, spec: &SwaggerSpec, base_url: &str, include_non_get: bool) -> Vec<SampleRequest> {
        let mut samples = Vec::new();

        // Determine the base path
        let base_path = if let Some(servers) = &spec.servers {
            servers.first().map(|s| s.url.clone()).unwrap_or_else(|| base_url.to_string())
        } else if let Some(base_path) = &spec.base_path {
            format!("{}{}", base_url, base_path)
        } else {
            base_url.to_string()
        };

        if let Some(paths) = &spec.paths {
            for (path, methods) in paths {
                for (method, path_item) in methods {
                    // Skip non-GET methods if risk flag is not set
                    if !include_non_get && method.to_uppercase() != "GET" {
                        continue;
                    }

                    let full_url = format!("{}{}", base_path.trim_end_matches('/'), path);
                    let mut headers = HashMap::new();
                    let mut query_params = HashMap::new();
                    let mut body = None;

                    // Add custom headers
                    for (key, value) in &self.custom_headers {
                        headers.insert(key.clone(), value.clone());
                    }

                    // Process parameters
                    if let Some(parameters) = &path_item.parameters {
                        for param in parameters {
                            let example_value = self.get_example_value(&param.schema, &param.example, &param.examples);
                            
                            match param.location.as_str() {
                                "query" => {
                                    query_params.insert(param.name.clone(), example_value);
                                }
                                "header" => {
                                    headers.insert(param.name.clone(), example_value);
                                }
                                _ => {}
                            }
                        }
                    }

                    // Process request body for POST/PUT/PATCH
                    if method.to_uppercase() == "POST" || method.to_uppercase() == "PUT" || method.to_uppercase() == "PATCH" {
                        if let Some(request_body) = &path_item.request_body {
                            if let Some(content) = &request_body.content {
                                if let Some(json_content) = content.get("application/json") {
                                    headers.insert("Content-Type".to_string(), "application/json".to_string());
                                    body = Some(self.generate_body_example(json_content));
                                }
                            }
                        }
                    }

                    // Generate cURL command
                    let curl_command = self.generate_curl_command(method, &full_url, &headers,
                        &if query_params.is_empty() { None } else { Some(query_params.clone()) }, &body);

                    samples.push(SampleRequest {
                        method: method.to_uppercase(),
                        url: full_url.clone(),
                        path: path.clone(),
                        headers,
                        query_params: if query_params.is_empty() { None } else { Some(query_params) },
                        body,
                        description: None,
                        curl_command,
                    });
                }
            }
        }

        samples
    }

    fn generate_curl_command(&self, method: &str, url: &str, headers: &HashMap<String, String>, 
                            query_params: &Option<HashMap<String, String>>, body: &Option<String>) -> String {
        let mut curl_parts = vec![format!("curl -X {}", method.to_uppercase())];
        
        // Add URL with query parameters
        let mut full_url = url.to_string();
        if let Some(params) = query_params {
            if !params.is_empty() {
                let query_string: Vec<String> = params.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect();
                full_url = format!("{}?{}", url, query_string.join("&"));
            }
        }
        curl_parts.push(format!("'{}'", full_url));
        
        // Add headers
        for (key, value) in headers {
            curl_parts.push(format!("-H '{}: {}'", key, value));
        }
        
        // Add body
        if let Some(body_content) = body {
            curl_parts.push(format!("-d '{}'", body_content));
        }
        
        curl_parts.join(" ")
    }

    fn get_example_value(&self, schema: &Option<Schema>, example: &Option<Value>, examples: &Option<HashMap<String, Example>>) -> String {
        // Try to get example from various sources
        if let Some(ex) = example {
            return self.value_to_string(ex);
        }

        if let Some(exs) = examples {
            if let Some(first_ex) = exs.values().next() {
                if let Some(val) = &first_ex.value {
                    return self.value_to_string(val);
                }
            }
        }

        if let Some(sch) = schema {
            if let Some(ex) = &sch.example {
                return self.value_to_string(ex);
            }

            if let Some(enum_vals) = &sch.enum_values {
                if let Some(first) = enum_vals.first() {
                    return self.value_to_string(first);
                }
            }

            // Generate default based on type
            if let Some(schema_type) = &sch.schema_type {
                match schema_type.as_str() {
                    "string" => return "example_string".to_string(),
                    "integer" | "number" => return "123".to_string(),
                    "boolean" => return "true".to_string(),
                    "array" => return "[]".to_string(),
                    "object" => return "{}".to_string(),
                    _ => {}
                }
            }
        }

        "example".to_string()
    }

    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => serde_json::to_string(value).unwrap_or_else(|_| "example".to_string()),
        }
    }

    fn generate_body_example(&self, content: &ContentType) -> String {
        if let Some(example) = &content.example {
            return serde_json::to_string_pretty(example).unwrap_or_else(|_| "{}".to_string());
        }

        if let Some(examples) = &content.examples {
            if let Some(first_ex) = examples.values().next() {
                if let Some(val) = &first_ex.value {
                    return serde_json::to_string_pretty(val).unwrap_or_else(|_| "{}".to_string());
                }
            }
        }

        if let Some(schema) = &content.schema {
            return self.generate_schema_example(schema);
        }

        "{}".to_string()
    }

    fn generate_schema_example(&self, schema: &Schema) -> String {
        if let Some(example) = &schema.example {
            return serde_json::to_string_pretty(example).unwrap_or_else(|_| "{}".to_string());
        }

        if let Some(schema_type) = &schema.schema_type {
            match schema_type.as_str() {
                "object" => {
                    let mut obj = json!({});
                    if let Some(properties) = &schema.properties {
                        if let Some(obj_map) = obj.as_object_mut() {
                            for (prop_name, prop_schema) in properties {
                                let is_required = schema.required.as_ref()
                                    .map(|r| r.contains(prop_name))
                                    .unwrap_or(false);
                                
                                if is_required || properties.len() <= 5 {
                                    let prop_value = self.generate_property_value(prop_schema);
                                    obj_map.insert(prop_name.clone(), prop_value);
                                }
                            }
                        }
                    }
                    return serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{}".to_string());
                }
                "array" => {
                    if let Some(items) = &schema.items {
                        let item_value = self.generate_property_value(items);
                        return serde_json::to_string_pretty(&json!([item_value]))
                            .unwrap_or_else(|_| "[]".to_string());
                    }
                    return "[]".to_string();
                }
                "string" => return json!("example_string").to_string(),
                "integer" | "number" => return json!(123).to_string(),
                "boolean" => return json!(true).to_string(),
                _ => {}
            }
        }

        "{}".to_string()
    }

    fn generate_property_value(&self, schema: &Schema) -> Value {
        if let Some(example) = &schema.example {
            return example.clone();
        }

        if let Some(enum_values) = &schema.enum_values {
            if let Some(first) = enum_values.first() {
                return first.clone();
            }
        }

        if let Some(schema_type) = &schema.schema_type {
            match schema_type.as_str() {
                "string" => json!("example_string"),
                "integer" => json!(123),
                "number" => json!(123.45),
                "boolean" => json!(true),
                "array" => json!([]),
                "object" => json!({}),
                _ => json!(null),
            }
        } else {
            json!(null)
        }
    }

    /// Generate parameter value combinations for brute forcing
    fn generate_brute_combinations(
        &self,
        parameters: &Option<Vec<Parameter>>,
        body_schema: Option<&Schema>,
    ) -> Vec<BruteCombination> {
        let mut combinations = Vec::new();

        if !self.brute_config.enabled {
            return combinations;
        }

        // Get query parameters that can be brute forced
        let mut query_params: Vec<(&Parameter, Vec<String>)> = Vec::new();
        if let Some(params) = parameters {
            for param in params {
                if param.location == "query" {
                    let param_type = param.param_type.as_deref()
                        .or_else(|| param.schema.as_ref().and_then(|s| s.schema_type.as_deref()));
                    let values = self.brute_config.get_values_for_type(param_type);
                    if !values.is_empty() {
                        query_params.push((param, values));
                    }
                }
            }
        }

        // Generate query parameter combinations (one param at a time with brute values)
        for (param, values) in &query_params {
            for value in values {
                let combo: Vec<(String, String)> = vec![(param.name.clone(), value.clone())];
                combinations.push((combo, None));

                if combinations.len() >= self.brute_config.limit {
                    return combinations;
                }
            }
        }

        // Generate body parameter combinations for POST/PUT/PATCH
        if let Some(schema) = body_schema {
            if let Some(properties) = &schema.properties {
                for (prop_name, prop_schema) in properties {
                    let prop_type = prop_schema.schema_type.as_deref();
                    let values = self.brute_config.get_values_for_type(prop_type);

                    for value in values {
                        // Create a body with just this property set to the brute value
                        let body_value = match prop_type {
                            Some("integer") | Some("number") => {
                                if let Ok(n) = value.parse::<i64>() {
                                    json!({ prop_name.clone(): n })
                                } else {
                                    json!({ prop_name.clone(): value })
                                }
                            }
                            Some("boolean") => {
                                let bool_val = value == "true" || value == "1" || value == "yes";
                                json!({ prop_name.clone(): bool_val })
                            }
                            _ => json!({ prop_name.clone(): value }),
                        };

                        combinations.push((Vec::new(), Some(body_value)));

                        if combinations.len() >= self.brute_config.limit {
                            return combinations;
                        }
                    }
                }
            }
        }

        combinations
    }

    async fn test_endpoints(&self, spec: &SwaggerSpec, base_url: &str, risk: bool, _all: bool, _product: bool) -> Vec<TestResult> {
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

                    // Get body schema for brute forcing
                    let body_schema = path_item.request_body.as_ref()
                        .and_then(|rb| rb.content.as_ref())
                        .and_then(|c| c.get("application/json"))
                        .and_then(|ct| ct.schema.as_ref());

                    // Generate brute force combinations
                    let brute_combinations = self.generate_brute_combinations(
                        &path_item.parameters,
                        body_schema,
                    );

                    // Create test cases: normal + brute force
                    let mut test_cases: Vec<(QueryParamCombos, Option<Value>, bool)> = vec![
                        (Vec::new(), None, false) // Normal test case
                    ];

                    // Add brute force test cases
                    for (query_params, body) in brute_combinations {
                        test_cases.push((query_params, body, true));
                    }

                    for (brute_query_params, brute_body, is_brute) in test_cases {
                        let full_url = format!("{}{}", base_path.trim_end_matches('/'), path);
                        let client = self.client.clone();
                        let method_clone = method.clone();
                        let path_clone = path.clone();
                        let path_item_clone = path_item.clone();
                        let rate_limiter = self.rate_limiter.clone();
                        let rate_delay = self.rate_delay;
                        let verbose = self.verbose;
                        let custom_headers = self.custom_headers.clone();
                        let total_requests = self.total_requests.clone();

                        let task = tokio::spawn(async move {
                            let _permit = rate_limiter.acquire().await.unwrap();

                            // Apply rate limiting delay before each request
                            sleep(rate_delay).await;

                            // Build URL with query parameters
                            let mut url_with_params = full_url.clone();
                            let mut query_params = Vec::new();

                            // Process normal parameters first
                            if let Some(parameters) = &path_item_clone.parameters {
                                for param in parameters {
                                    if param.location == "query" {
                                        // Check if this param has a brute force override
                                        let brute_value = brute_query_params.iter()
                                            .find(|(name, _)| name == &param.name)
                                            .map(|(_, v)| v.clone());

                                        let value = brute_value.unwrap_or_else(|| {
                                            if let Some(ex) = &param.example {
                                                match ex {
                                                    Value::String(s) => s.clone(),
                                                    Value::Number(n) => n.to_string(),
                                                    Value::Bool(b) => b.to_string(),
                                                    _ => "example".to_string(),
                                                }
                                            } else {
                                                "example".to_string()
                                            }
                                        });

                                        query_params.push((param.name.clone(), value));
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
                                url_with_params.push('?');
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

                            // Add header parameters from spec
                            if let Some(parameters) = &path_item_clone.parameters {
                                for param in parameters {
                                    if param.location == "header" {
                                        let example_value = if let Some(ex) = &param.example {
                                            match ex {
                                                Value::String(s) => s.clone(),
                                                Value::Number(n) => n.to_string(),
                                                Value::Bool(b) => b.to_string(),
                                                _ => "example".to_string(),
                                            }
                                        } else {
                                            "example".to_string()
                                        };
                                        request = request.header(&param.name, example_value);
                                    }
                                }
                            }

                            // Add request body for POST/PUT/PATCH
                            let method_upper = method_clone.to_uppercase();
                            if method_upper == "POST" || method_upper == "PUT" || method_upper == "PATCH" {
                                // Use brute force body if provided, otherwise use example
                                if let Some(brute_body_value) = &brute_body {
                                    request = request.header("Content-Type", "application/json");
                                    let body_str = serde_json::to_string(brute_body_value)
                                        .unwrap_or_else(|_| "{}".to_string());
                                    body_content = body_str.clone();
                                    request = request.body(body_str);
                                } else if let Some(request_body) = &path_item_clone.request_body {
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
                                let brute_tag = if is_brute { " [BRUTE]" } else { "" };
                                println!("[TEST]{} {} {}", brute_tag, method_clone.to_uppercase(), url_with_params);
                                if !body_content.is_empty() && is_brute {
                                    println!("       Body: {}", body_content);
                                }
                            }

                            match request.send().await {
                                Ok(response) => {
                                    // Increment request counter after successful send
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
                                        url: url_with_params,
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
                                        custom_headers_used: if custom_headers.is_empty() { None } else { Some(custom_headers) },
                                    })
                                }
                                Err(e) => {
                                    if verbose {
                                        eprintln!("[ERROR] Failed to test {} {}: {}", method_clone, url_with_params, e);
                                    }
                                    None
                                }
                            }
                        });

                        tasks.push(task);
                    }
                }
            }

            // Wait for all tasks to complete
            let task_results = join_all(tasks).await;
            for result in task_results {
                if let Ok(Some(test_result)) = result {
                    results.push(test_result);
                }
            }
        }

        results
    }

    fn detect_pii(text: &str) -> PiiDetectionResult {
        let mut pii_data = HashMap::new();
        let mut detection_details = HashMap::new();
        let mut patterns_found = HashMap::new();
        let mut detection_methods = HashSet::new();

        // Enhanced PII detection patterns
        let patterns = [
            ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            ("phone", r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
            ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
            ("credit_card", r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"),
            ("ipv4", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            ("ipv6", r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"),
            ("date_of_birth", r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b"),
            ("api_key", r#"(?i)(?:api[_\-]?key|apikey|api_token)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})"#),
            ("bearer_token", r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
            ("aws_key", r#"(?:AKIA[0-9A-Z]{16}|aws[_\-]?(?:access[_\-]?key[_\-]?id|secret[_\-]?access[_\-]?key))["']?\s*[:=]\s*["']?([a-zA-Z0-9/+=]{20,})"#),
            ("private_key", r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
            ("jwt", r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
        ];

        for (pattern_name, pattern_str) in patterns.iter() {
            let re = Regex::new(pattern_str).unwrap();
            let matches: Vec<String> = re.find_iter(text)
                .map(|m| m.as_str().to_string())
                .collect();
            
            if !matches.is_empty() {
                pii_data.insert(pattern_name.to_string(), matches);
                patterns_found.insert(pattern_name.to_string(), pattern_str.to_string());
                detection_methods.insert(format!("regex_{}", pattern_name));
                
                detection_details.insert(
                    pattern_name.to_string(),
                    DetectionDetails {
                        detection_methods: vec![format!("regex_{}", pattern_name)],
                    },
                );
            }
        }

        // Check for common PII field names in JSON structure
        let field_indicators = [
            "email", "phone", "ssn", "social_security", "credit_card", 
            "date_of_birth", "dob", "address", "passport", "driver_license",
            "bank_account", "routing_number", "tax_id", "national_id",
            "username", "password", "api_key", "secret", "token", "auth",
        ];

        for indicator in field_indicators.iter() {
            if text.to_lowercase().contains(indicator) {
                detection_methods.insert(format!("field_name_{}", indicator));
                
                let entry = detection_details.entry(format!("field_indicator_{}", indicator))
                    .or_insert_with(|| DetectionDetails {
                        detection_methods: Vec::new(),
                    });
                entry.detection_methods.push(format!("field_name_{}", indicator));
            }
        }

        let has_pii = !pii_data.is_empty() || !detection_details.is_empty();
        
        (
            has_pii,
            if has_pii { Some(pii_data) } else { None },
            if has_pii { Some(detection_details) } else { None },
            patterns_found,
            detection_methods,
        )
    }

    fn is_interesting_response(text: &str, status_code: u16) -> bool {
        // Consider responses interesting based on various criteria
        if status_code == 200 && text.len() > 1000 {
            return true;
        }

        // Check for error messages that might reveal information
        let interesting_patterns = [
            "error", "exception", "stack trace", "debug", "warning",
            "unauthorized", "forbidden", "internal server",
        ];

        for pattern in interesting_patterns.iter() {
            if text.to_lowercase().contains(pattern) {
                return true;
            }
        }

        false
    }

    async fn calculate_stats(&self, urls: &[String], results: &[TestResult], hosts_with_spec: usize, hosts_with_endpoint: usize, proxy_used: bool) -> ScanStats {
        let unique_hosts: HashSet<String> = urls.iter()
            .filter_map(|url| {
                Url::parse(url).ok().or_else(|| {
                    Url::parse(&format!("https://{}", url)).ok()
                }).map(|u| u.host_str().unwrap_or("").to_string())
            })
            .collect();

        let active_hosts = unique_hosts.len();
        
        let hosts_with_pii: HashSet<String> = results.iter()
            .filter(|r| r.pii_detected)
            .filter_map(|r| Url::parse(&r.url).ok())
            .map(|u| u.host_str().unwrap_or("").to_string())
            .collect();

        let all_detection_methods: HashSet<String> = results.iter()
            .flat_map(|r| r.pii_detection_methods.iter().cloned())
            .collect();

        let all_regexes: HashSet<String> = results.iter()
            .flat_map(|r| r.regex_patterns_found.keys().cloned())
            .collect();

        let percentage = if active_hosts > 0 {
            (hosts_with_endpoint as f64 / active_hosts as f64) * 100.0
        } else {
            0.0
        };

        let total_requests = *self.total_requests.lock().await;
        let elapsed_secs = self.scan_start.elapsed().as_secs_f64();
        let avg_rps = if elapsed_secs > 0.0 {
            total_requests as f64 / elapsed_secs
        } else {
            0.0
        };

        ScanStats {
            unique_hosts_provided: unique_hosts.len(),
            active_hosts,
            hosts_with_valid_spec: hosts_with_spec,
            hosts_with_valid_endpoint: hosts_with_endpoint,
            hosts_with_pii: hosts_with_pii.len(),
            pii_detection_methods: all_detection_methods.into_iter().collect(),
            percentage_hosts_with_endpoint: percentage,
            regexes_found: all_regexes.into_iter().collect(),
            total_requests_sent: total_requests,
            average_requests_per_second: avg_rps,
            custom_headers_count: self.custom_headers.len(),
            proxy_used,
        }
    }
}

fn print_banner() {
    println!(r#"
 _____         _             _____               
| __  |_ _ ___| |_ _ _      |   __|_ _ _ ___ ___ 
|    -| | |_ -|  _| | |     |__   | | | | .'| . |
|__|__|___|___|_| |_  |_____|_____|_____|__,|_  |
                  |___|_____|               |___|
                          Analyze Swagger and OpenAPI Endpoints
    "#);
}

fn parse_headers(header_strings: &[String]) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
    
    for header_str in header_strings {
        // Split by the first colon
        if let Some(colon_pos) = header_str.find(':') {
            let (key, value) = header_str.split_at(colon_pos);
            let value = &value[1..]; // Skip the colon
            
            // Trim whitespace from both key and value
            let key = key.trim();
            let value = value.trim();
            
            if key.is_empty() {
                eprintln!("[WARN] Invalid header format (empty key): {}", header_str);
                continue;
            }
            
            headers.insert(key.to_string(), value.to_string());
        } else {
            eprintln!("[WARN] Invalid header format (no colon found): {}", header_str);
        }
    }
    
    Ok(headers)
}

fn save_samples_to_file(samples: &[SampleRequest], dir_path: &str, args: &Args) -> Result<()> {
    // Create directory if it doesn't exist
    let dir = Path::new(dir_path);
    fs::create_dir_all(dir)?;
    
    // Generate timestamp for unique filenames
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    
    println!("[INFO] Saving {} HTTP requests to directory: {}", samples.len(), dir_path);
    
    for (index, sample) in samples.iter().enumerate() {
        // Create a sanitized filename based on method and path
        let path_part = sample.path
            .replace("/", "_")
            .replace("{", "")
            .replace("}", "")
            .replace("?", "")
            .replace("&", "")
            .replace("=", "")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect::<String>();
        
        let filename = format!("{:03}_{}_{}_{}.txt", 
            index + 1,
            sample.method.to_lowercase(),
            path_part,
            timestamp
        );
        
        let file_path = dir.join(&filename);
        let mut file = fs::File::create(&file_path)?;
        
        // Build the raw HTTP request
        let mut http_request = String::new();
        
        // Request line
        let mut url_with_params = sample.url.clone();
        if let Some(query_params) = &sample.query_params {
            if !query_params.is_empty() {
                let query_string: Vec<String> = query_params.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect();
                // Check if URL already has query parameters
                if sample.url.contains('?') {
                    url_with_params.push_str(&format!("&{}", query_string.join("&")));
                } else {
                    url_with_params.push_str(&format!("?{}", query_string.join("&")));
                }
            }
        }
        
        // Parse URL to extract path and query for HTTP request line
        let parsed_url = match Url::parse(&url_with_params) {
            Ok(u) => u,
            Err(_) => {
                eprintln!("[WARN] Failed to parse URL for request {}: {}", index + 1, sample.url);
                continue;
            }
        };
        
        let path_and_query = if let Some(query) = parsed_url.query() {
            format!("{}?{}", parsed_url.path(), query)
        } else {
            parsed_url.path().to_string()
        };
        
        // HTTP request line
        http_request.push_str(&format!("{} {} HTTP/1.1\r\n", sample.method, path_and_query));
        
        // Host header (required for HTTP/1.1)
        if let Some(host) = parsed_url.host_str() {
            let host_with_port = if let Some(port) = parsed_url.port() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            };
            http_request.push_str(&format!("Host: {}\r\n", host_with_port));
        }
        
        // Add other headers
        for (key, value) in &sample.headers {
            http_request.push_str(&format!("{}: {}\r\n", key, value));
        }
        
        // Add Content-Length header if there's a body
        if let Some(body) = &sample.body {
            let content_length = body.len();
            // Only add Content-Length if not already present
            if !sample.headers.contains_key("Content-Length") {
                http_request.push_str(&format!("Content-Length: {}\r\n", content_length));
            }
        }
        
        // Add Connection header if not present
        if !sample.headers.contains_key("Connection") {
            http_request.push_str("Connection: close\r\n");
        }
        
        // Add User-Agent if not present
        if !sample.headers.contains_key("User-Agent") {
            http_request.push_str("User-Agent: Rusty-Swag/1.0\r\n");
        }
        
        // Empty line to separate headers from body
        http_request.push_str("\r\n");
        
        // Add body if present
        if let Some(body) = &sample.body {
            http_request.push_str(body);
        }
        
        // Write to file
        file.write_all(http_request.as_bytes())?;
        
        if args.verbose {
            println!("[SAVED] Request #{} -> {}", index + 1, file_path.display());
        }
    }
    
    println!("[SUCCESS] Saved {} HTTP request(s) to directory: {}", samples.len(), dir_path);
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !args.product {
        print_banner();
    }

    // Parse custom headers
    let custom_headers = parse_headers(&args.headers)?;
    
    if !custom_headers.is_empty() && args.verbose {
        println!("[INFO] Parsed {} custom header(s):", custom_headers.len());
        for (key, value) in &custom_headers {
            println!("  {}: {}", key, value);
        }
    }

    // Display proxy information if provided
    if let Some(proxy) = &args.proxy {
        if !args.product {
            println!("[INFO] Using proxy: {}", proxy);
        }
    }

    // Create brute force configuration
    let brute_config = BruteConfig::new(args.brute, args.wordlist.clone(), args.brute_limit);

    if args.brute && !args.product {
        println!("[INFO] Brute force mode enabled with {} payloads (limit: {} per endpoint)",
            brute_config.values.len(), brute_config.limit);
    }

    let scanner = Scanner::new(args.verbose, args.rate, custom_headers.clone(), args.proxy.clone(), brute_config);
    let mut all_results = Vec::new();
    let mut all_samples = Vec::new();
    let mut hosts_with_spec = 0;
    let mut hosts_with_endpoint = 0;

    println!("[INFO] Processing {} URLs...", args.urls.len());
    if !custom_headers.is_empty() {
        println!("[INFO] Using {} custom header(s) for all requests", custom_headers.len());
    }

    for url in &args.urls {
        let (results, found_spec, samples) = scanner.process_url(
            url, 
            args.risk, 
            args.all, 
            args.product,
            args.samples
        ).await;

        if found_spec {
            hosts_with_spec += 1;
        }

        if !results.is_empty() {
            hosts_with_endpoint += 1;
        }

        all_results.extend(results);
        if let Some(sample_requests) = samples {
            all_samples.extend(sample_requests);
        }
    }

    // Filter results based on flags
    let filtered_results: Vec<_> = if args.all {
        all_results.into_iter()
            .filter(|r| r.status_code != 401 && r.status_code != 403)
            .collect()
    } else {
        all_results.into_iter()
            .filter(|r| r.status_code == 200)
            .collect()
    };

    // Calculate statistics
    let stats = scanner.calculate_stats(&args.urls, &filtered_results, hosts_with_spec, hosts_with_endpoint, args.proxy.is_some()).await;

    // Save samples to file if flag is set and samples exist
    if args.samples && !all_samples.is_empty() {
        if let Err(e) = save_samples_to_file(&all_samples, &args.samples_dir, &args) {
            eprintln!("[ERROR] Failed to save samples to file: {}", e);
        }
    }

    // Output results
    if args.samples && !all_samples.is_empty() {
        if args.json || args.product {
            let output = json!({
                "sample_requests": all_samples,
                "results": if args.product || args.json { Some(filtered_results) } else { None::<Vec<TestResult>> },
                "stats": if args.stats { Some(stats) } else { None::<ScanStats> },
                "custom_headers": if !custom_headers.is_empty() { Some(custom_headers) } else { None::<HashMap<String, String>> },
                "proxy": args.proxy,
                "samples_saved_to_directory": format!("{}/", args.samples_dir)
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("\n=== Sample HTTP Requests Saved ===");
            println!("Location: ./{}/", args.samples_dir);
            println!("Total requests saved: {}", all_samples.len());
            println!("\nFile format: <index>_<method>_<path>_<timestamp>.txt");
            println!("Each file contains a raw HTTP request that can be sent directly to the server.");
            
            if !custom_headers.is_empty() {
                println!("\nNote: All requests include {} custom header(s)", custom_headers.len());
            }
            if args.proxy.is_some() {
                println!("Note: Proxy configuration should be applied when sending these requests");
            }
            
            println!("\nSample files created:");
            for (i, sample) in all_samples.iter().enumerate().take(5) {
                println!("  {}. {} {}", i + 1, sample.method, sample.path);
            }
            if all_samples.len() > 5 {
                println!("  ... and {} more", all_samples.len() - 5);
            }
            
            if !filtered_results.is_empty() && !args.product {
                println!("\n=== Test Results ===");
                for result in &filtered_results {
                    let custom_headers_note = if result.custom_headers_used.is_some() {
                        " [with custom headers]"
                    } else {
                        ""
                    };
                    println!("{} {} [{}] - {} bytes{}{}",
                        result.method,
                        result.url,
                        result.status_code,
                        result.content_length,
                        if result.pii_detected { " [PII DETECTED]" } else { "" },
                        custom_headers_note
                    );
                    if !result.body.is_empty() && args.verbose {
                        println!("   Request body: {}", result.body);
                    }
                }
            }
        }
    } else if args.product || args.json {
        let output = json!({
            "results": filtered_results,
            "stats": if args.stats { Some(stats) } else { None },
            "custom_headers": if !custom_headers.is_empty() { Some(custom_headers) } else { None::<HashMap<String, String>> },
            "proxy": args.proxy
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if !filtered_results.is_empty() {
            println!("\n=== API Endpoints Found ===");
            for result in &filtered_results {
                let custom_headers_note = if result.custom_headers_used.is_some() {
                    " [with custom headers]"
                } else {
                    ""
                };
                println!("{} {} [{}] - {} bytes{}{}",
                    result.method,
                    result.url,
                    result.status_code,
                    result.content_length,
                    if result.pii_detected { " [PII DETECTED]" } else { "" },
                    custom_headers_note
                );
                if !result.body.is_empty() && args.verbose {
                    println!("   Request body: {}", result.body);
                }
            }
        } else {
            println!("[INFO] No valid API responses found.");
        }

        if args.stats {
            println!("\n=== Scan Statistics ===");
            println!("Unique hosts provided: {}", stats.unique_hosts_provided);
            println!("Active hosts: {}", stats.active_hosts);
            println!("Hosts with valid spec: {}", stats.hosts_with_valid_spec);
            println!("Hosts with valid endpoint: {}", stats.hosts_with_valid_endpoint);
            println!("Hosts with PII: {}", stats.hosts_with_pii);
            println!("Percentage hosts with endpoint: {:.2}%", stats.percentage_hosts_with_endpoint);
            println!("Total requests sent: {}", stats.total_requests_sent);
            println!("Average requests per second: {:.2}", stats.average_requests_per_second);
            if stats.custom_headers_count > 0 {
                println!("Custom headers used: {}", stats.custom_headers_count);
            }
            if stats.proxy_used {
                println!("Proxy: Enabled");
            }
        }
    }

    Ok(())
}