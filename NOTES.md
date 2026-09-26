# Enterprise Extension Notes

What was added on top of the existing PCAP Forensic Analyzer, and how to run it.
All original modules (`pcap_parser.py`, `calculate_statistics.py`, `ioc_extractor.py`,
`hashing.py`, `detectors/*.py`, `report_generator.py`, `communication_graph.py`,
`visualization/charts.py`) are unmodified — everything below wraps them.

## 1. Performance caching (`performance.py`)

**Problem it fixes:** Streamlit reruns the entire script on every widget
interaction. Previously, typing in the packet-viewer search box re-parsed the
whole pcap and re-ran all four detectors from scratch.

**What changed:** `app.py` now calls `parse_pcap_cached`, `calculate_hashes_cached`,
`calculate_statistics_cached`, `extract_iocs_cached`, `run_all_detectors_cached`,
and `create_graph_figure_cached` instead of the raw functions. Each is a
`@st.cache_data`-wrapped pass-through to the original, untouched function —
keyed on the uploaded file's bytes (+ `max_packets`), so re-analysis only
happens when the input actually changes. A `profile_time` decorator logs
per-stage timing to stdout if you want to confirm where time is going on a
real capture.

No caching is silently stale: Streamlit's `cache_data` hashes the actual
argument values, so a different file or a different packet cap always
produces a fresh result.

## 2. UI theme (`config.py`, `design_system.py`, `ui_components.py`, `assets/theme.css`)

`design_system.py` holds color/typography/spacing tokens and a Plotly dark
template. `assets/theme.css` is the stylesheet consuming those tokens as CSS
variables. `ui_components.py` has the render functions (`inject_theme`,
`render_hero_banner`, `render_metric_card`, `render_status_chip`,
`style_plotly_figure`, `render_footer`) that `app.py` calls. Nothing here
changes what data is shown, only how.

Toggle it off entirely by setting `enable_custom_theme = False` in `config.py`.

## 3. MCP server (`mcp_server/`)

Lets an AI assistant (Claude Desktop, Claude Code, or any MCP client) call
your analysis pipeline directly, without opening the dashboard.

**Important naming note:** the package is called `mcp_server`, not `mcp`.
Naming it `mcp` would shadow the installed `mcp` SDK package and break its
own `from mcp.server.fastmcp import FastMCP` import — this was caught during
testing and fixed by renaming.

**Also note:** the MCP repo you originally pointed at
(`https://github.com/PortSwigger/mcp-server`) is a Kotlin/JVM Burp Suite
extension with no plugin surface for hosting unrelated Python tools — it
can't be "integrated into" the way a Python library can. This server is a
standalone build using Anthropic's official Python `mcp` SDK instead,
exposing your exact requested tool list.

**Run it:**
```bash
pip install -r requirements.txt
python -m mcp_server.server
```

**Register it with Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/absolute/path/to/pcap-analyzer"
    }
  }
}
```

**Tools exposed** (all take `pcap_path`, most take optional `max_packets`):
`analyze_pcap`, `calculate_statistics`, `extract_iocs`, `detect_port_scan`,
`detect_beaconing`, `detect_dns_tunneling`, `detect_plaintext_credentials`,
`generate_report`, `generate_network_graph`, `calculate_hash`, `summary`.

Each tool call parses the file once and caches the parsed records in-process
(keyed on absolute path + mtime + `max_packets`), so asking for `summary`
then `generate_report` on the same file doesn't re-parse twice. Errors
(missing file, unparseable capture) return `{"error": "..."}` with an
actionable message instead of a raw exception.

Tested end-to-end against a synthetic capture (port scan, DNS query,
plaintext credential, and beaconing-style traffic) — all 11 tools verified
to return correct results, including the not-found error path.

## 4. Rust acceleration (`rust/`, `rust_bridge.py`, `accelerated.py`) -- added after initial delivery

Initially skipped for the 3-4 hour budget; added afterward on request. See
`RUST.md` for full details, verified correctness methodology, and honest
benchmark numbers (4.4x on entropy scoring, 2.7x on graph edge aggregation --
real speedups, modest in absolute terms since both operations are sub-second
even in Python at realistic capture sizes).

Key points:
- `detectors/dns_tunneling.py` and `communication_graph.py` are **not modified**.
  `accelerated.py` is a new module that reuses their constants/helpers and
  swaps only the entropy calculation / edge-counting step for Rust.
- Falls back to pure Python automatically if the extension isn't built --
  verified by uninstalling it and re-running the full test suite (still 11/11 passing).
- Toggle via `config.py`: `enable_rust_acceleration`.

## 5. Requirements fix

`plotly` and `networkx` were already imported by `app.py` and
`communication_graph.py` but were missing from `requirements.txt` — a fresh
`pip install -r requirements.txt` would not have actually run the app. Added
both, plus `mcp` for the new server.

## 6. Frontend refinement pass (design reference adaptation)

Adjusted `design_system.py` (typography scale, spacing, single restrained
accent instead of a loud dual-color gradient wash) and `assets/theme.css`
(calmer hero banner, more spacious metric cards, pill-shaped buttons)
after a request to adapt the visual language of a referenced design
(getdesign.md's ventriloc listing).

**Honest limitation**: getdesign.md gates the actual DESIGN.md token file
(exact hex codes, font-family names, spacing scale) behind a paid "request"
flow -- I could only see the catalog page and screenshots, not extracted
values. What's here is my interpretation of the visible visual language
(generous whitespace, confident large typography, restrained single-accent
color, soft high-radius cards) adapted to work as a **dark** SOC dashboard,
since the reference itself is a light B2B marketing site and a literal
light-theme port would look out of place next to the Defender XDR/Falcon-style
references this project was already following. If you have the actual
DESIGN.md file (or exact hex values you want matched), send them over and
I'll match them precisely instead of approximating from screenshots.
