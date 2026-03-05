//! PyO3 bindings for the wirefilter expression parser.
//!
//! Exposes `parse_expression(expr: str, phase: str | None) -> dict` to Python.
//! Returns extracted components on success or `{"error": "..."}` on parse failure.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

mod scheme;
mod visitor;

use scheme::get_scheme;
use visitor::ExpressionExtractor;

/// Parse a Cloudflare wirefilter expression and return extracted components.
///
/// The optional `phase` parameter selects the appropriate wirefilter scheme:
/// - Transform phases (`url_rewrite_rules`, `request_header_rules`,
///   `response_header_rules`) use a scheme where `http.request.uri.path`
///   is a callable function.
/// - All other phases (or `None`) use the default scheme where
///   `http.request.uri.path` is a regular field.
///
/// Returns a Python dict with:
///   - On success: {"fields": [...], "functions": [...], "operators": [...], ...}
///   - On failure: {"error": "parse error description"}
#[pyfunction]
#[pyo3(signature = (expr, phase=None))]
fn parse_expression(py: Python<'_>, expr: &str, phase: Option<&str>) -> PyResult<PyObject> {
    // Empty expressions are valid — return empty lists (not an error).
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        let dict = PyDict::new(py);
        let empty: Vec<String> = Vec::new();
        dict.set_item("fields", PyList::new(py, &empty)?)?;
        dict.set_item("functions", PyList::new(py, &empty)?)?;
        dict.set_item("operators", PyList::new(py, &empty)?)?;
        dict.set_item("string_literals", PyList::new(py, &empty)?)?;
        dict.set_item("regex_literals", PyList::new(py, &empty)?)?;
        dict.set_item("ip_literals", PyList::new(py, &empty)?)?;
        let empty_ints: Vec<i64> = Vec::new();
        dict.set_item("int_literals", PyList::new(py, &empty_ints)?)?;
        return Ok(dict.into());
    }

    // Parse the expression against the phase-appropriate scheme.
    let scheme = get_scheme(phase);
    let ast = match scheme.parse(trimmed) {
        Ok(ast) => ast,
        Err(e) => {
            let dict = PyDict::new(py);
            dict.set_item("error", format!("{e}"))?;
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
    dict.set_item("string_literals", PyList::new(py, &extractor.string_literals)?)?;
    dict.set_item("regex_literals", PyList::new(py, &extractor.regex_literals)?)?;
    dict.set_item("ip_literals", PyList::new(py, &extractor.ip_literals)?)?;
    dict.set_item("int_literals", PyList::new(py, &extractor.int_literals)?)?;
    Ok(dict.into())
}

/// Python module definition.
#[pymodule]
fn octorules_wirefilter(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_expression, m)?)?;
    Ok(())
}
