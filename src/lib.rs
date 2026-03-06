//! PyO3 bindings for the wirefilter expression parser.
//!
//! Exposes `parse_expression(expr: str, phase: str | None) -> dict` to Python.
//! Returns extracted components on success or `{"error": "..."}` on parse failure.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

mod scheme;
mod visitor;

use scheme::{TRANSFORM_PHASES, get_scheme};
use visitor::ExpressionExtractor;

/// Maximum allowed expression length (1 MiB).
const MAX_EXPRESSION_LEN: usize = 1_048_576;

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
///   - On success: `{"fields": [...], "functions": [...], "operators": [...], ...}`
///   - On failure: `{"error": "parse error description"}`
///
/// Empty or whitespace-only expressions are valid and return empty lists
/// for all keys (not an error dict).
#[pyfunction]
#[pyo3(signature = (expr, phase=None))]
fn parse_expression(py: Python<'_>, expr: &str, phase: Option<&str>) -> PyResult<Py<PyAny>> {
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
        return Ok(dict.into());
    }

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
    dict.set_item(
        "string_literals",
        PyList::new(py, &extractor.string_literals)?,
    )?;
    dict.set_item(
        "regex_literals",
        PyList::new(py, &extractor.regex_literals)?,
    )?;
    dict.set_item("ip_literals", PyList::new(py, &extractor.ip_literals)?)?;
    dict.set_item("int_literals", PyList::new(py, &extractor.int_literals)?)?;
    if extractor.depth_exceeded() {
        dict.set_item("depth_exceeded", true)?;
    }
    Ok(dict.into())
}

/// Return schema metadata for the wirefilter scheme.
///
/// Returns a Python dict with:
///   - `fields`: list of `{"name": "...", "type": "STRING"}` dicts
///   - `functions`: list of function name strings
///   - `transform_phases`: list of transform phase name strings
///   - `transform_field_as_function`: the field that becomes a function in transform phases
#[pyfunction]
fn get_schema_info(py: Python<'_>) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);

    // Fields
    let field_defs = scheme::common_field_defs();
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

    // Transform phases
    dict.set_item("transform_phases", PyList::new(py, TRANSFORM_PHASES)?)?;

    // The field that becomes a function in transform phases
    dict.set_item("transform_field_as_function", "http.request.uri.path")?;

    Ok(dict.into())
}

/// Python module definition.
#[pymodule]
fn octorules_wirefilter(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_expression, m)?)?;
    m.add_function(wrap_pyfunction!(get_schema_info, m)?)?;
    Ok(())
}
