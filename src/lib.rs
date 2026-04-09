//! # cuda-filtration
//!
//! Intelligence filtration — security gates, performance filters, correctness checks.
//! Every decision passes through filters before becoming action.
//!
//! ```rust
//! use cuda_filtration::{FiltrationEngine, FilterRule, FilterCategory, Severity};
//! use cuda_equipment::Confidence;
//!
//! let mut engine = FiltrationEngine::new();
//! engine.add_default_security_rules();
//! let result = engine.filter("response", "execute rm -rf /", Confidence::SURE);
//! assert!(result.blocked);
//! ```

pub use cuda_equipment::{Confidence, VesselId};

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FilterCategory {
    Security,
    Performance,
    Correctness,
    Privacy,
    Resource,
    Compliance,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Block,
    Warn,
    Info,
    Pass,
}

/// A single filtration rule.
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub id: String,
    pub category: FilterCategory,
    pub severity: Severity,
    pub pattern: String,
    pub description: String,
    pub confidence_threshold: f64,
}

impl FilterRule {
    pub fn new(id: &str, category: FilterCategory, severity: Severity, pattern: &str, desc: &str) -> Self {
        Self { id: id.to_string(), category, severity, pattern: pattern.to_string(),
            description: desc.to_string(), confidence_threshold: 0.5 }
    }

    pub fn with_threshold(mut self, t: f64) -> Self { self.confidence_threshold = t; self }

    /// Check if input matches this rule's pattern.
    pub fn matches(&self, input: &str) -> bool {
        if self.pattern.is_empty() { return false; }
        let input_lower = input.to_lowercase();
        let pattern_lower = self.pattern.to_lowercase();
        // Simple substring matching (real impl would use regex)
        if pattern_lower.contains('*') {
            let parts: Vec<&str> = pattern_lower.split('*').collect();
            parts.iter().all(|p| input_lower.contains(*p))
        } else {
            input_lower.contains(&pattern_lower)
        }
    }
}

/// Result of filtering one input.
#[derive(Debug, Clone)]
pub struct FilterResult {
    pub passed: bool,
    pub blocked: bool,
    pub warnings: Vec<FilterHit>,
    pub infos: Vec<FilterHit>,
    pub final_confidence: Confidence,
    pub applied_rules: usize,
}

#[derive(Debug, Clone)]
pub struct FilterHit {
    pub rule_id: String,
    pub category: FilterCategory,
    pub severity: Severity,
    pub description: String,
    pub matched_pattern: String,
}

/// Filtration engine — runs all rules against inputs.
pub struct FiltrationEngine {
    rules: Vec<FilterRule>,
    stats: FiltrationStats,
}

impl FiltrationEngine {
    pub fn new() -> Self {
        Self { rules: vec![], stats: FiltrationStats::default() }
    }

    pub fn add_rule(&mut self, rule: FilterRule) { self.rules.push(rule); }

    /// Add default security rules.
    pub fn add_default_security_rules(&mut self) {
        self.add_rule(FilterRule::new("sec-destruct", FilterCategory::Security, Severity::Block,
            "rm -rf", "Destructive file deletion"));
        self.add_rule(FilterRule::new("sec-sudo-rm", FilterCategory::Security, Severity::Block,
            "sudo rm", "Privileged deletion"));
        self.add_rule(FilterRule::new("sec-format", FilterCategory::Security, Severity::Block,
            "format disk", "Disk formatting"));
        self.add_rule(FilterRule::new("sec-shutdown", FilterCategory::Security, Severity::Warn,
            "shutdown", "System shutdown"));
        self.add_rule(FilterRule::new("sec-reboot", FilterCategory::Security, Severity::Warn,
            "reboot", "System reboot"));
        self.add_rule(FilterRule::new("sec-credential", FilterCategory::Privacy, Severity::Block,
            "password=", "Credential in output"));
        self.add_rule(FilterRule::new("sec-api-key", FilterCategory::Privacy, Severity::Block,
            "api_key=", "API key exposure"));
        self.add_rule(FilterRule::new("sec-token", FilterCategory::Privacy, Severity::Warn,
            "bearer", "Token exposure"));
        self.add_rule(FilterRule::new("perf-large", FilterCategory::Performance, Severity::Info,
            ">100GB", "Large data transfer"));
        self.add_rule(FilterRule::new("perf-slow", FilterCategory::Performance, Severity::Warn,
            "O(n^3)", "Cubic complexity detected"));
    }

    /// Filter an input through all rules.
    pub fn filter(&mut self, domain: &str, input: &str, confidence: Confidence) -> FilterResult {
        self.stats.total_filtered += 1;
        let mut result = FilterResult {
            passed: true, blocked: false, warnings: vec![], infos: vec![],
            final_confidence: confidence, applied_rules: 0,
        };

        for rule in &self.rules {
            if rule.matches(input) {
                result.applied_rules += 1;
                let hit = FilterHit {
                    rule_id: rule.id.clone(), category: rule.category.clone(),
                    severity: rule.severity.clone(),
                    description: rule.description.clone(),
                    matched_pattern: rule.pattern.clone(),
                };
                match rule.severity {
                    Severity::Block => {
                        result.blocked = true;
                        result.passed = false;
                        result.final_confidence = Confidence::ZERO;
                        self.stats.blocked += 1;
                        // Short-circuit on block
                        return result;
                    }
                    Severity::Warn => {
                        result.warnings.push(hit);
                        result.final_confidence = result.final_confidence.discount(0.85);
                        self.stats.warned += 1;
                    }
                    Severity::Info => {
                        result.infos.push(hit);
                        self.stats.informed += 1;
                    }
                    Severity::Pass => {}
                }
            }
        }

        if result.warnings.len() >= 3 {
            self.stats.warned_to_blocked += 1;
        }
        result
    }

    /// Filter with domain-specific confidence threshold.
    pub fn filter_with_threshold(&mut self, domain: &str, input: &str,
        confidence: Confidence, threshold: f64) -> FilterResult {
        let result = self.filter(domain, input, confidence);
        if result.final_confidence.value() < threshold {
            FilterResult { passed: false, blocked: true,
                warnings: result.warnings, infos: result.infos,
                final_confidence: Confidence::ZERO, applied_rules: result.applied_rules }
        } else { result }
    }

    pub fn stats(&self) -> &FiltrationStats { &self.stats }
    pub fn rule_count(&self) -> usize { self.rules.len() }

    /// Get rules by category.
    pub fn rules_by_category(&self, cat: &FilterCategory) -> Vec<&FilterRule> {
        self.rules.iter().filter(|r| &r.category == cat).collect()
    }
}

impl Default for FiltrationEngine { fn default() -> Self { Self::new() } }

/// Filtration statistics.
#[derive(Debug, Clone, Default)]
pub struct FiltrationStats {
    pub total_filtered: u64,
    pub blocked: u64,
    pub warned: u64,
    pub informed: u64,
    pub warned_to_blocked: u64,
}

impl FiltrationStats {
    pub fn block_rate(&self) -> f64 {
        if self.total_filtered == 0 { return 0.0; }
        self.blocked as f64 / self.total_filtered as f64
    }
    pub fn warn_rate(&self) -> f64 {
        if self.total_filtered == 0 { return 0.0; }
        self.warned as f64 / self.total_filtered as f64
    }
}

/// Resource budget — limits what an agent can consume.
#[derive(Debug, Clone)]
pub struct ResourceBudget {
    pub max_tokens: u64,
    pub max_memory_mb: u64,
    pub max_wall_time_secs: u64,
    pub max_api_calls: u64,
    tokens_used: u64,
    memory_used_mb: u64,
    wall_time_secs: u64,
    api_calls: u64,
}

impl ResourceBudget {
    pub fn new(max_tokens: u64, max_memory_mb: u64, max_wall_time: u64, max_api_calls: u64) -> Self {
        Self { max_tokens, max_memory_mb, max_wall_time_secs: max_wall_time, max_api_calls,
            tokens_used: 0, memory_used_mb: 0, wall_time_secs: 0, api_calls: 0 }
    }

    /// Check if an action is within budget.
    pub fn check(&self, tokens: u64, memory_mb: u64, wall_secs: u64, api_calls: u64) -> BudgetCheck {
        let token_ok = self.tokens_used + tokens <= self.max_tokens;
        let mem_ok = self.memory_used_mb + memory_mb <= self.max_memory_mb;
        let time_ok = self.wall_time_secs + wall_secs <= self.max_wall_time_secs;
        let api_ok = self.api_calls + api_calls <= self.max_api_calls;
        let all_ok = token_ok && mem_ok && time_ok && api_ok;
        BudgetCheck { allowed: all_ok,
            token_ok, memory_ok: mem_ok, time_ok, api_calls_ok: api_ok,
            remaining_tokens: self.max_tokens - self.tokens_used,
            remaining_memory_mb: self.max_memory_mb - self.memory_used_mb,
        }
    }

    pub fn consume(&mut self, tokens: u64, memory_mb: u64, wall_secs: u64, api_calls: u64) {
        self.tokens_used += tokens;
        self.memory_used_mb += memory_mb;
        self.wall_time_secs += wall_secs;
        self.api_calls += api_calls;
    }

    pub fn usage_fraction(&self) -> f64 {
        let fractions = [
            self.tokens_used as f64 / self.max_tokens.max(1) as f64,
            self.memory_used_mb as f64 / self.max_memory_mb.max(1) as f64,
            self.wall_time_secs as f64 / self.max_wall_time_secs.max(1) as f64,
            self.api_calls as f64 / self.max_api_calls.max(1) as f64,
        ];
        fractions.into_iter().fold(0.0f64, |a, b| a.max(b))
    }
}

#[derive(Debug, Clone)]
pub struct BudgetCheck {
    pub allowed: bool,
    pub token_ok: bool,
    pub memory_ok: bool,
    pub time_ok: bool,
    pub api_calls_ok: bool,
    pub remaining_tokens: u64,
    pub remaining_memory_mb: u64,
}

/// Default budgets per agent tier.
pub struct BudgetTiers;

impl BudgetTiers {
    pub fn scout() -> ResourceBudget { ResourceBudget::new(4000, 512, 30, 10) }
    pub fn messenger() -> ResourceBudget { ResourceBudget::new(8000, 1024, 60, 25) }
    pub fn navigator() -> ResourceBudget { ResourceBudget::new(16000, 2048, 120, 50) }
    pub fn captain() -> ResourceBudget { ResourceBudget::new(32000, 4096, 300, 100) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_destructive() {
        let mut engine = FiltrationEngine::new();
        engine.add_default_security_rules();
        let result = engine.filter("response", "execute rm -rf /", Confidence::SURE);
        assert!(result.blocked);
        assert!(!result.passed);
    }

    #[test]
    fn test_pass_safe() {
        let mut engine = FiltrationEngine::new();
        engine.add_default_security_rules();
        let result = engine.filter("response", "hello world", Confidence::SURE);
        assert!(result.passed);
        assert!(!result.blocked);
    }

    #[test]
    fn test_warn_shutdown() {
        let mut engine = FiltrationEngine::new();
        engine.add_default_security_rules();
        let result = engine.filter("system", "initiate shutdown", Confidence::SURE);
        assert!(result.passed); // warnings don't block
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_privacy_block() {
        let mut engine = FiltrationEngine::new();
        engine.add_default_security_rules();
        let result = engine.filter("output", "password=secret123", Confidence::SURE);
        assert!(result.blocked);
    }

    #[test]
    fn test_wildcard_pattern() {
        let mut engine = FiltrationEngine::new();
        engine.add_rule(FilterRule::new("test", FilterCategory::Security, Severity::Block,
            "*sudo*rm*", "sudo with rm"));
        let result = engine.filter("cmd", "sudo rm -rf /", Confidence::SURE);
        assert!(result.blocked);
    }

    #[test]
    fn test_stats() {
        let mut engine = FiltrationEngine::new();
        engine.add_default_security_rules();
        engine.filter("a", "safe", Confidence::SURE);
        engine.filter("b", "rm -rf /", Confidence::SURE);
        assert_eq!(engine.stats().total_filtered, 2);
        assert_eq!(engine.stats().blocked, 1);
    }

    #[test]
    fn test_confidence_discount() {
        let mut engine = FiltrationEngine::new();
        engine.add_default_security_rules();
        let result = engine.filter("system", "system shutdown now", Confidence::SURE);
        assert!(result.final_confidence.value() < 1.0); // discounted by warning
    }

    #[test]
    fn test_resource_budget() {
        let budget = ResourceBudget::new(1000, 512, 60, 10);
        let check = budget.check(500, 256, 30, 5);
        assert!(check.allowed);
        assert_eq!(check.remaining_tokens, 1000);
    }

    #[test]
    fn test_budget_exceeded() {
        let mut budget = ResourceBudget::new(100, 50, 10, 2);
        let check = budget.check(200, 0, 0, 0);
        assert!(!check.allowed);
        assert!(!check.token_ok);
    }

    #[test]
    fn test_budget_tiers() {
        let scout = BudgetTiers::scout();
        let captain = BudgetTiers::captain();
        assert!(captain.max_tokens > scout.max_tokens);
    }

    #[test]
    fn test_threshold_filter() {
        let mut engine = FiltrationEngine::new();
        engine.add_default_security_rules();
        let result = engine.filter_with_threshold("low", "shutdown", Confidence::UNLIKELY, 0.5);
        assert!(result.blocked); // confidence too low for threshold
    }

    #[test]
    fn test_rules_by_category() {
        let mut engine = FiltrationEngine::new();
        engine.add_default_security_rules();
        let sec_rules = engine.rules_by_category(&FilterCategory::Security);
        assert!(sec_rules.len() >= 4);
    }
}
