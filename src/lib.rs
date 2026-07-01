//! PyO3 bindings for the wirefilter expression parser.
//!
//! Exposes `parse_expression(expr, scheme=None)` and `get_schema_info(scheme=None)`
//! to Python. `parse_expression` returns extracted components on success or
//! `{"error": "..."}` on parse failure; `scheme` selects the HTTP or
//! `"magic_firewall"` (Layer-4) field set.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use wirefilter::ParserSettings;

mod scheme;
mod visitor;

use scheme::{SCHEME, SCHEME_MAGIC};
use visitor::ExpressionExtractor;

/// Maximum allowed expression length (1 MiB).
const MAX_EXPRESSION_LEN: usize = 1_048_576;

/// Conservative parser settings to catch likely-rejected expressions early.
///
/// - `wildcard_star_limit`: 10 — prevents excessive `*` metacharacters that
///   would cause catastrophic backtracking at evaluation time.
/// - Regex size limits: wirefilter defaults (10 MB DFA, 2 MB compiled).
pub(crate) fn parser_settings() -> ParserSettings {
    ParserSettings {
        wildcard_star_limit: 10,
        ..ParserSettings::default()
    }
}

/// Standard result keys returned by `parse_expression`.
const RESULT_KEYS: &[&str] = &[
    "fields",
    "functions",
    "operators",
    "string_literals",
    "regex_literals",
    "regex_field_pairs",
    "ip_literals",
    "int_literals",
];

/// Populate a Python dict with empty lists for all standard result keys.
fn set_empty_result_keys(py: Python<'_>, dict: &Bound<'_, PyDict>) -> PyResult<()> {
    for key in RESULT_KEYS {
        dict.set_item(*key, PyList::empty(py))?;
    }
    Ok(())
}

/// Parse a Cloudflare wirefilter expression and return extracted components.
///
/// The `scheme` parameter selects the field scheme: `"magic_firewall"` uses
/// the packet-level Layer-4 scheme (`SCHEME_MAGIC`); any other value (or
/// `None`) uses the default HTTP `SCHEME`. The caller maps its ruleset phases
/// to a selector — e.g. octorules-cloudflare maps its account-level Magic
/// Transit phases to `"magic_firewall"`.
///
/// Returns a Python dict with:
///   - On success: `{"fields": [...], "functions": [...], "operators": [...], ...}`
///   - On failure: `{"error": "parse error description", "fields": [], ...}` —
///     the error string plus every standard result key present as an empty list.
///
/// Empty or whitespace-only expressions are valid and return empty lists
/// for all keys (not an error dict).
#[pyfunction]
#[pyo3(signature = (expr, scheme=None))]
fn parse_expression(py: Python<'_>, expr: &str, scheme: Option<&str>) -> PyResult<Py<PyAny>> {
    // Reject oversized expressions before any processing.
    if expr.len() > MAX_EXPRESSION_LEN {
        let dict = PyDict::new(py);
        dict.set_item(
            "error",
            format!(
                "expression exceeds maximum length ({} bytes, limit {})",
                expr.len(),
                MAX_EXPRESSION_LEN
            ),
        )?;
        set_empty_result_keys(py, &dict)?;
        return Ok(dict.into());
    }

    // Empty expressions are valid — return empty lists (not an error).
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        let dict = PyDict::new(py);
        set_empty_result_keys(py, &dict)?;
        return Ok(dict.into());
    }

    // Select the field scheme. Account-level Magic Transit (Layer-4) phases use
    // the packet-level SCHEME_MAGIC; everything else uses the HTTP SCHEME.
    let parsed = match scheme {
        Some("magic_firewall") => SCHEME_MAGIC
            .parser_with_settings(parser_settings())
            .parse(trimmed),
        _ => SCHEME
            .parser_with_settings(parser_settings())
            .parse(trimmed),
    };
    let ast = match parsed {
        Ok(ast) => ast,
        Err(e) => {
            let dict = PyDict::new(py);
            dict.set_item("error", format!("{e}"))?;
            set_empty_result_keys(py, &dict)?;
            return Ok(dict.into());
        }
    };

    // Walk the AST to extract components.
    let mut extractor = ExpressionExtractor::new();
    extractor.extract(ast.expression());

    // Build the result dict.
    let dict = PyDict::new(py);
    dict.set_item("fields", PyList::new(py, &extractor.fields)?)?;
    dict.set_item("functions", PyList::new(py, &extractor.functions)?)?;
    dict.set_item("operators", PyList::new(py, &extractor.operators)?)?;
    dict.set_item(
        "string_literals",
        PyList::new(py, &extractor.string_literals)?,
    )?;
    dict.set_item(
        "regex_literals",
        PyList::new(py, &extractor.regex_literals)?,
    )?;
    // (field, regex) tuples — populated when the LHS of `matches` is a
    // plain field. Empty for function-call LHS or non-matches operators.
    // Consumers like CF546 (suspicious_regex) use this for per-field
    // heuristics that can't be expressed against the flat regex_literals
    // list alone.
    let pairs = PyList::empty(py);
    for (field, regex) in &extractor.regex_field_pairs {
        let pair = PyList::new(py, [field.as_str(), regex.as_str()])?;
        pairs.append(pair)?;
    }
    dict.set_item("regex_field_pairs", pairs)?;
    dict.set_item("ip_literals", PyList::new(py, &extractor.ip_literals)?)?;
    dict.set_item("int_literals", PyList::new(py, &extractor.int_literals)?)?;
    if extractor.depth_exceeded() {
        dict.set_item("depth_exceeded", true)?;
    }
    Ok(dict.into())
}

/// Return schema metadata for a wirefilter scheme.
///
/// `scheme` selects the field set: `"magic_firewall"` returns the Layer-4
/// (Magic Transit) fields; any other value (or `None`) returns the default
/// HTTP fields. Mirrors `parse_expression`'s `scheme` argument so callers can
/// build a per-scheme field registry from a single source.
///
/// Returns a Python dict with:
///   - `fields`: list of `{"name": "...", "type": "STRING"}` dicts
///   - `functions`: list of function name strings
#[pyfunction]
#[pyo3(signature = (scheme=None))]
fn get_schema_info(py: Python<'_>, scheme: Option<&str>) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);

    // Fields
    let field_defs = match scheme {
        Some("magic_firewall") => scheme::magic_field_defs(),
        _ => scheme::common_field_defs(),
    };
    let fields_list = PyList::empty(py);
    for (name, py_type) in field_defs {
        let entry = PyDict::new(py);
        entry.set_item("name", *name)?;
        entry.set_item("type", *py_type)?;
        fields_list.append(entry)?;
    }
    dict.set_item("fields", fields_list)?;

    // Functions
    let func_names = scheme::common_function_names();
    dict.set_item("functions", PyList::new(py, func_names)?)?;

    Ok(dict.into())
}

/// Python module definition.
#[pymodule]
fn octorules_wirefilter(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_expression, m)?)?;
    m.add_function(wrap_pyfunction!(get_schema_info, m)?)?;
    Ok(())
}
