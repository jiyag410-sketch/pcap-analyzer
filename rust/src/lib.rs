//! pcap_rust_accel
//!
//! PyO3 extension exposing accelerated versions of two hot paths identified
//! during profiling of the PCAP Forensic Analyzer:
//!
//!   1. Shannon entropy per string (detectors/dns_tunneling.py::_entropy) --
//!      called once per DNS subdomain, and DNS-tunneling-heavy captures can
//!      have tens of thousands of queries to the same root domain.
//!
//!   2. Communication-graph edge aggregation (communication_graph.py::build_graph's
//!      inner loop) -- O(n) over every packet record to count src->dst pairs.
//!
//! Both functions are direct, verified ports of the existing Python logic --
//! same math, same output for the same input (see rust_bridge.py's
//! correctness self-check, which compares this extension's output against
//! the pure-Python fallback on every import). Nothing about detection
//! thresholds or graph semantics changes; this crate only recomputes the
//! same values faster.

use pyo3::prelude::*;
use std::collections::HashMap;

/// Shannon entropy in bits/char of a single string, matching
/// detectors/dns_tunneling.py::_entropy exactly (frequency count over
/// characters, -sum(p * log2(p))).
#[pyfunction]
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, u64> = HashMap::new();
    let mut length: u64 = 0;
    for ch in s.chars() {
        *freq.entry(ch).or_insert(0) += 1;
        length += 1;
    }

    let length_f = length as f64;
    -freq
        .values()
        .map(|&c| {
            let p = c as f64 / length_f;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Batched version of shannon_entropy -- avoids one Python<->Rust call per
/// string, which matters when a DNS-tunneling-heavy capture has thousands
/// of subdomains to score for a single root domain.
#[pyfunction]
fn batch_shannon_entropy(strings: Vec<String>) -> Vec<f64> {
    strings.iter().map(|s| shannon_entropy(s)).collect()
}

/// Aggregates (src_ip, dst_ip) pairs into (src, dst, count) edges, preserving
/// first-appearance order -- matching the effect of communication_graph.py's
/// sequential G.add_edge()/G[src][dst]["count"] += 1 loop, just computed in
/// one Rust pass instead of a Python loop over every packet record.
#[pyfunction]
fn aggregate_edges(pairs: Vec<(String, String)>) -> Vec<(String, String, u64)> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut counts: HashMap<(String, String), u64> = HashMap::new();

    for (src, dst) in pairs {
        let key = (src, dst);
        let entry = counts.entry(key.clone()).or_insert(0);
        if *entry == 0 {
            order.push(key.clone());
        }
        *entry += 1;
    }

    order
        .into_iter()
        .map(|key| {
            let count = counts[&key];
            (key.0, key.1, count)
        })
        .collect()
}

#[pymodule]
fn pcap_rust_accel(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(batch_shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(aggregate_edges, m)?)?;
    Ok(())
}
