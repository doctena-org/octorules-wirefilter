//! AST visitor that extracts fields, functions, operators, and literals
//! from a parsed wirefilter expression.

use std::collections::HashSet;
use std::fmt::Display;
use std::net::IpAddr;
use std::ops::RangeInclusive;

use wirefilter::{
    ComparisonExpr, ComparisonOpExpr, ExplicitIpRange, FunctionCallArgExpr, IdentifierExpr,
    IndexExpr, IntOp, IntRange, IpRange, LogicalExpr, LogicalOp, OrderingOp, RhsValue, RhsValues,
    UnaryOp,
};

/// Maximum nesting depth before the extractor stops descending.
const MAX_NESTING_DEPTH: usize = 100;

/// Generate a dedup-add method that uses `HashSet::insert()` to avoid the
/// `contains` + `insert` double-lookup, and allocates once (for the set)
/// then clones (for the vec) per unique entry.
macro_rules! dedup_add {
    ($method:ident, $seen:ident, $list:ident) => {
        fn $method(&mut self, value: &str) {
            let owned = value.to_owned();
            if self.$seen.insert(owned.clone()) {
                self.$list.push(owned);
            }
        }
    };
}

/// Extracts all components from a wirefilter AST for the ExpressionInfo contract.
pub struct ExpressionExtractor {
    pub fields: Vec<String>,
    pub functions: Vec<String>,
    pub operators: Vec<String>,
    pub string_literals: Vec<String>,
    pub regex_literals: Vec<String>,
    pub ip_literals: Vec<String>,
    pub int_literals: Vec<i64>,

    seen_fields: HashSet<String>,
    seen_functions: HashSet<String>,
    seen_operators: HashSet<String>,
    seen_strings: HashSet<String>,
    seen_regexes: HashSet<String>,
    seen_ips: HashSet<String>,
    seen_ints: HashSet<i64>,

    depth: usize,
    max_depth_exceeded: bool,
}

impl ExpressionExtractor {
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
            functions: Vec::new(),
            operators: Vec::new(),
            string_literals: Vec::new(),
            regex_literals: Vec::new(),
            ip_literals: Vec::new(),
            int_literals: Vec::new(),
            seen_fields: HashSet::new(),
            seen_functions: HashSet::new(),
            seen_operators: HashSet::new(),
            seen_strings: HashSet::new(),
            seen_regexes: HashSet::new(),
            seen_ips: HashSet::new(),
            seen_ints: HashSet::new(),
            depth: 0,
            max_depth_exceeded: false,
        }
    }

    /// Returns true if the extractor hit the maximum nesting depth.
    pub fn depth_exceeded(&self) -> bool {
        self.max_depth_exceeded
    }

    dedup_add!(add_field, seen_fields, fields);
    dedup_add!(add_function, seen_functions, functions);
    dedup_add!(add_operator, seen_operators, operators);
    dedup_add!(add_string, seen_strings, string_literals);
    dedup_add!(add_regex, seen_regexes, regex_literals);
    dedup_add!(add_ip, seen_ips, ip_literals);

    fn add_int(&mut self, val: i64) {
        if self.seen_ints.insert(val) {
            self.int_literals.push(val);
        }
    }

    /// Extract an IP address as a string.
    fn extract_ip(&mut self, addr: &IpAddr) {
        self.add_ip(&addr.to_string());
    }

    /// Extract RHS value literals.
    fn extract_rhs_value(&mut self, rhs: &RhsValue) {
        match rhs {
            RhsValue::Bytes(bytes_expr) => {
                self.add_string(&String::from_utf8_lossy(bytes_expr));
            }
            RhsValue::Int(i) => self.add_int(*i),
            RhsValue::Ip(addr) => self.extract_ip(addr),
            RhsValue::Bool(_) | RhsValue::Array(_) | RhsValue::Map(_) => {}
        }
    }

    /// Extract int from an IntRange (single value or range endpoints).
    fn extract_int_range(&mut self, range: &IntRange) {
        let r: RangeInclusive<i64> = range.into();
        let start = *r.start();
        let end = *r.end();
        self.add_int(start);
        if end != start {
            self.add_int(end);
        }
    }

    /// Extract start (and end if different) from an explicit IP range.
    fn extract_explicit_ip_range<T: Display + PartialEq>(&mut self, start: &T, end: &T) {
        self.add_ip(&start.to_string());
        if start != end {
            self.add_ip(&end.to_string());
        }
    }

    /// Extract IP from an IpRange.
    fn extract_ip_range(&mut self, range: &IpRange) {
        match range {
            IpRange::Cidr(cidr) => {
                self.add_ip(&cidr.to_string());
            }
            IpRange::Explicit(explicit) => match explicit {
                ExplicitIpRange::V4(r) => self.extract_explicit_ip_range(r.start(), r.end()),
                ExplicitIpRange::V6(r) => self.extract_explicit_ip_range(r.start(), r.end()),
            },
        }
    }

    /// Extract literals from an RhsValues set (used in `in {...}` expressions).
    fn extract_rhs_values(&mut self, values: &RhsValues) {
        match values {
            RhsValues::Bytes(items) => {
                for item in items {
                    self.add_string(&String::from_utf8_lossy(item));
                }
            }
            RhsValues::Int(ranges) => {
                for range in ranges {
                    self.extract_int_range(range);
                }
            }
            RhsValues::Ip(ranges) => {
                for range in ranges {
                    self.extract_ip_range(range);
                }
            }
            RhsValues::Bool(_) | RhsValues::Array(_) | RhsValues::Map(_) => {}
        }
    }

    /// Walk a comparison operator and extract the operator name + RHS literals.
    fn extract_comparison_op(&mut self, op: &ComparisonOpExpr) {
        match op {
            ComparisonOpExpr::IsTrue => {
                // Bare field truthiness — no explicit operator.
            }
            ComparisonOpExpr::Ordering { op: ord_op, rhs } => {
                self.add_operator(match ord_op {
                    OrderingOp::Equal => "eq",
                    OrderingOp::NotEqual => "ne",
                    OrderingOp::GreaterThan => "gt",
                    OrderingOp::GreaterThanEqual => "ge",
                    OrderingOp::LessThan => "lt",
                    OrderingOp::LessThanEqual => "le",
                });
                self.extract_rhs_value(rhs);
            }
            ComparisonOpExpr::Int { op, rhs } => {
                self.add_operator(match op {
                    IntOp::BitwiseAnd => "bitwise_and",
                });
                self.add_int(*rhs);
            }
            ComparisonOpExpr::Contains(bytes_expr) => {
                self.add_operator("contains");
                self.add_string(&String::from_utf8_lossy(bytes_expr));
            }
            ComparisonOpExpr::Matches(regex) => {
                self.add_operator("matches");
                self.add_regex(&regex.to_string());
            }
            ComparisonOpExpr::Wildcard(wc) => {
                self.add_operator("wildcard");
                self.add_string(&String::from_utf8_lossy(wc.pattern()));
            }
            ComparisonOpExpr::StrictWildcard(wc) => {
                self.add_operator("strict_wildcard");
                self.add_string(&String::from_utf8_lossy(wc.pattern()));
            }
            ComparisonOpExpr::OneOf(values) => {
                self.add_operator("in");
                self.extract_rhs_values(values);
            }
            ComparisonOpExpr::ContainsOneOf(items) => {
                self.add_operator("contains");
                self.add_operator("in");
                for item in items {
                    self.add_string(&String::from_utf8_lossy(item));
                }
            }
            ComparisonOpExpr::InList { .. } => {
                self.add_operator("in");
            }
        }
    }

    /// Recursively walk an IndexExpr to extract fields and functions.
    fn walk_index_expr(&mut self, index_expr: &IndexExpr) {
        match index_expr.identifier() {
            IdentifierExpr::Field(field) => {
                self.add_field(field.name());
            }
            IdentifierExpr::FunctionCallExpr(func_call) => {
                self.add_function(func_call.function().name());
                for arg in func_call.args() {
                    self.walk_function_arg(arg);
                }
            }
        }
    }

    /// Walk a function call argument.
    fn walk_function_arg(&mut self, arg: &FunctionCallArgExpr) {
        if self.depth >= MAX_NESTING_DEPTH {
            self.max_depth_exceeded = true;
            return;
        }
        self.depth += 1;
        match arg {
            FunctionCallArgExpr::IndexExpr(index_expr) => {
                self.walk_index_expr(index_expr);
            }
            FunctionCallArgExpr::Literal(rhs) => {
                self.extract_rhs_value(rhs);
            }
            FunctionCallArgExpr::Logical(logical) => {
                self.walk_logical(logical);
            }
        }
        self.depth -= 1;
    }

    /// Recursively walk a logical expression tree.
    fn walk_logical(&mut self, expr: &LogicalExpr) {
        if self.depth >= MAX_NESTING_DEPTH {
            self.max_depth_exceeded = true;
            return;
        }
        self.depth += 1;
        match expr {
            LogicalExpr::Combining { op, items } => {
                self.add_operator(match op {
                    LogicalOp::And => "and",
                    LogicalOp::Or => "or",
                    LogicalOp::Xor => "xor",
                });
                for item in items {
                    self.walk_logical(item);
                }
            }
            LogicalExpr::Comparison(cmp) => {
                self.walk_comparison(cmp);
            }
            LogicalExpr::Parenthesized(paren) => {
                self.walk_logical(&paren.expr);
            }
            LogicalExpr::Unary { op, arg } => {
                match op {
                    UnaryOp::Not => self.add_operator("not"),
                }
                self.walk_logical(arg);
            }
        }
        self.depth -= 1;
    }

    /// Walk a comparison expression: LHS + operator + RHS literals.
    fn walk_comparison(&mut self, cmp: &ComparisonExpr) {
        self.walk_index_expr(cmp.lhs_expr());
        self.extract_comparison_op(cmp.operator());
    }

    /// Entry point: walk the root LogicalExpr of a FilterAst.
    pub fn extract(&mut self, root: &LogicalExpr) {
        self.walk_logical(root);
    }
}
