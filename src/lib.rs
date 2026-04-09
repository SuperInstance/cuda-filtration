//! Intelligence Filtration — real-time insight extraction from deliberation streams
//! Filters bad ideas, security holes, anti-patterns from agent proposals.

use std::collections::{HashMap, HashSet};

/// A filter rule — pattern that proposals are checked against
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub id: String,
    pub category: FilterCategory,
    pub pattern: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterCategory {
    Security,
    Performance,
    Correctness,
    Style,
    Compatibility,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Block,      // Hard block — proposal must be rejected
    Warn,       // Warning — proposal can proceed but flagged
    Info,       // Informational — logged but no action
}

/// Filter result for a single proposal
#[derive(Debug, Clone)]
pub struct FilterResult {
    pub proposal_id: usize,
    pub passed: bool,
    pub violations: Vec<FilterViolation>,
    pub score_adjustment: f64,
}

#[derive(Debug, Clone)]
pub struct FilterViolation {
    pub rule_id: String,
    pub category: FilterCategory,
    pub severity: Severity,
    pub message: String,
    pub suggestion: Option<String>,
}

/// The filtration engine
pub struct FiltrationEngine {
    rules: Vec<FilterRule>,
    history: Vec<FilterResult>,
    block_cache: HashSet<String>,
}

impl FiltrationEngine {
    pub fn new() -> Self {
        Self {
            rules: default_rules(),
            history: vec![],
            block_cache: HashSet::new(),
        }
    }

    /// Add a custom filter rule
    pub fn add_rule(&mut self, rule: FilterRule) {
        self.rules.push(rule);
    }

    /// Filter a proposal — returns violations and adjusted score
    pub fn filter(&mut self, proposal_id: usize, code: &str, metadata: &HashMap<String, String>) -> FilterResult {
        let mut violations = vec![];
        let mut score_adj = 0.0;
        let code_lower = code.to_lowercase();

        for rule in &self.rules {
            if rule.pattern.is_empty() { continue; }
            let pattern_lower = rule.pattern.to_lowercase();

            // Check code against pattern
            let matches = if pattern_lower.starts_with("regex:") {
                // Simple substring matching for embedded (no regex crate)
                code_lower.contains(&pattern_lower[6..])
            } else {
                code_lower.contains(&pattern_lower)
            };

            if matches {
                let suggestion = match rule.category {
                    FilterCategory::Security => Some("Use parameterized queries or input validation".to_string()),
                    FilterCategory::Performance => Some("Consider caching or batch processing".to_string()),
                    FilterCategory::Correctness => Some("Add null checks and error handling".to_string()),
                    FilterCategory::Style => None,
                    FilterCategory::Compatibility => Some("Test across target platforms".to_string()),
                };

                violations.push(FilterViolation {
                    rule_id: rule.id.clone(), category: rule.category.clone(),
                    severity: rule.severity.clone(),
                    message: rule.description.clone(), suggestion,
                });

                score_adj += match rule.severity {
                    Severity::Block => -0.5,
                    Severity::Warn => -0.15,
                    Severity::Info => -0.02,
                };
            }
        }

        let passed = !violations.iter().any(|v| v.severity == Severity::Block);

        let result = FilterResult {
            proposal_id, passed, violations, score_adjustment: score_adj,
        };
        self.history.push(result.clone());
        result
    }

    /// Get statistics about filtered proposals
    pub fn stats(&self) -> FilterStats {
        let total = self.history.len();
        let passed = self.history.iter().filter(|r| r.passed).count();
        let blocked = total - passed;
        let violations: usize = self.history.iter().map(|r| r.violations.len()).sum();
        FilterStats { total, passed, blocked, total_violations: violations }
    }
}

#[derive(Debug, Clone)]
pub struct FilterStats {
    pub total: usize,
    pub passed: usize,
    pub blocked: usize,
    pub total_violations: usize,
}

/// Default security and quality rules
fn default_rules() -> Vec<FilterRule> {
    vec![
        FilterRule { id: "sec-eval".to_string(), category: FilterCategory::Security,
            pattern: "eval(".to_string(), severity: Severity::Block,
            description: "Arbitrary code execution via eval()".to_string() },
        FilterRule { id: "sec-sql".to_string(), category: FilterCategory::Security,
            pattern: "execute(".to_string(), severity: Severity::Block,
            description: "Raw SQL execution without parameterization".to_string() },
        FilterRule { id: "perf-n2".to_string(), category: FilterCategory::Performance,
            pattern: "O(n^2)".to_string(), severity: Severity::Warn,
            description: "Quadratic time complexity detected".to_string() },
        FilterRule { id: "corr-hardcoded".to_string(), category: FilterCategory::Correctness,
            pattern: "TODO".to_string(), severity: Severity::Warn,
            description: "Incomplete implementation (TODO)".to_string() },
        FilterRule { id: "comp-single".to_string(), category: FilterCategory::Compatibility,
            pattern: "thread::spawn".to_string(), severity: Severity::Info,
            description: "Platform-specific threading detected".to_string() },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_code_passes() {
        let mut engine = FiltrationEngine::new();
        let result = engine.filter(1, "return sorted(data, reverse=True)", &HashMap::new());
        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_eval_blocked() {
        let mut engine = FiltrationEngine::new();
        let result = engine.filter(2, "result = eval(user_input)", &HashMap::new());
        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| v.rule_id == "sec-eval"));
    }

    #[test]
    fn test_performance_warning() {
        let mut engine = FiltrationEngine::new();
        let result = engine.filter(3, "O(n^2) nested loop algorithm", &HashMap::new());
        assert!(result.passed); // warn doesn't block
        assert!(result.score_adjustment < 0.0);
    }

    #[test]
    fn test_stats() {
        let mut engine = FiltrationEngine::new();
        engine.filter(1, "safe code", &HashMap::new());
        engine.filter(2, "eval(x)", &HashMap::new());
        let stats = engine.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.passed, 1);
        assert_eq!(stats.blocked, 1);
    }
}
