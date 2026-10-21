#!/usr/bin/env python3
"""
Convert a Noxim mesh VCD trace into a self-contained HTML viewer.

This viewer is intentionally focused:
- mesh topology only
- cycle-by-cycle buffer/link inspection
- pure Python 3 stdlib
- no browser-side dependencies
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Optional, Tuple


FLIT_FIELDS = (
    "src_id",
    "dst_id",
    "vc_id",
    "flit_type",
    "sequence_no",
    "sequence_length",
    "timestamp",
    "hop_no",
    "use_low_voltage_path",
    "hub_relay_node",
)

CARDINAL_DIRECTIONS = ("north", "east", "south", "west")

FLIT_RE = re.compile(
    r"^flit\((\d+)\)\((\d+)\)\.(north|east|south|west)\."
    r"(src_id|dst_id|vc_id|flit_type|sequence_no|sequence_length|timestamp|hop_no|use_low_voltage_path|hub_relay_node)$"
)
FREE_SLOTS_RE = re.compile(r"^free_slots\((\d+)\)\((\d+)\)\.(north|east|south|west)$")
BUFFER_OCC_RE = re.compile(
    r"^router_buffer\((\d+)\)\((\d+)\)\.(north|east|south|west)\.vc(\d+)\.occupancy$"
)
BUFFER_SLOT_RE = re.compile(
    r"^router_buffer\((\d+)\)\((\d+)\)\.(north|east|south|west)\.vc(\d+)\.slot(\d+)\."
    r"(src_id|dst_id|vc_id|flit_type|sequence_no|sequence_length|timestamp|hop_no|use_low_voltage_path|hub_relay_node)$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a Noxim mesh VCD trace into a local HTML network viewer."
    )
    parser.add_argument("--vcd", required=True, help="Input VCD trace file")
    parser.add_argument("--output", required=True, help="Output HTML file")
    parser.add_argument(
        "--config",
        help="Optional Noxim YAML config file, used for topology and reset metadata",
    )
    return parser.parse_args()


def read_simple_config(path: Optional[str]) -> Dict[str, object]:
    if not path:
        return {}

    config: Dict[str, object] = {}
    wanted = {
        "topology",
        "mesh_dim_x",
        "mesh_dim_y",
        "clock_period_ps",
        "reset_time",
        "n_virtual_channels",
    }

    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        if key not in wanted:
            continue

        value = value.strip().strip('"').strip("'")
        if key in {"mesh_dim_x", "mesh_dim_y", "clock_period_ps", "reset_time", "n_virtual_channels"}:
            try:
                config[key] = int(value)
            except ValueError:
                pass
        else:
            config[key] = value

    return config


def parse_label(label: str) -> Optional[Dict[str, object]]:
    label = re.sub(r"\s+\[\d+:\d+\]$", "", label)

    match = FLIT_RE.match(label)
    if match:
        return {
            "kind": "link_flit",
            "x": int(match.group(1)),
            "y": int(match.group(2)),
            "direction": match.group(3),
            "field": match.group(4),
        }

    match = FREE_SLOTS_RE.match(label)
    if match:
        return {
            "kind": "free_slots",
            "x": int(match.group(1)),
            "y": int(match.group(2)),
            "direction": match.group(3),
        }

    match = BUFFER_OCC_RE.match(label)
    if match:
        return {
            "kind": "buffer_occupancy",
            "x": int(match.group(1)),
            "y": int(match.group(2)),
            "direction": match.group(3),
            "vc": int(match.group(4)),
        }

    match = BUFFER_SLOT_RE.match(label)
    if match:
        return {
            "kind": "buffer_slot",
            "x": int(match.group(1)),
            "y": int(match.group(2)),
            "direction": match.group(3),
            "vc": int(match.group(4)),
            "slot": int(match.group(5)),
            "field": match.group(6),
        }

    if label == "clock":
        return {"kind": "clock"}

    return None


def decode_value(token: str, width: int) -> Optional[object]:
    if not token:
        return None

    if token[0] in {"0", "1"} and len(token) == 1:
        return int(token)
    if token[0] in {"x", "z"} and len(token) == 1:
        return None

    if token[0] == "b":
        bits = token[1:]
        if any(ch in bits.lower() for ch in ("x", "z")):
            return None
        value = int(bits, 2)
        if width > 1 and len(bits) == width and bits[0] == "1":
            value -= 1 << width
        return value

    if token[0] == "r":
        try:
            return float(token[1:])
        except ValueError:
            return None

    return None


def encode_key(*parts: object) -> str:
    return "|".join(str(part) for part in parts)


def default_for_key(_key: str) -> int:
    return 0


def normalize_update(key: str, value: Optional[object]) -> Optional[object]:
    if value is None:
        return None
    if value == default_for_key(key):
        return None
    return value


def parse_vcd(path: str) -> Tuple[Dict[str, Dict[str, object]], Dict[int, Dict[str, object]], Optional[str]]:
    var_map: Dict[str, Dict[str, object]] = {}
    changes_by_time: Dict[int, Dict[str, object]] = defaultdict(dict)
    clock_code: Optional[str] = None

    in_definitions = True
    current_time = 0

    for raw_line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if in_definitions:
            if line.startswith("$var"):
                match = re.match(r"^\$var\s+\S+\s+(\d+)\s+(\S+)\s+(.+?)\s+\$end$", line)
                if not match:
                    continue

                width = int(match.group(1))
                code = match.group(2)
                label = match.group(3)
                metadata = parse_label(label)
                if metadata:
                    metadata["width"] = width
                    metadata["label"] = label
                    var_map[code] = metadata
                if label == "clock":
                    clock_code = code
            elif line.startswith("$enddefinitions"):
                in_definitions = False
            continue

        if line.startswith("#"):
            current_time = int(line[1:])
            continue

        if line.startswith("$"):
            continue

        if line[0] in {"0", "1", "x", "z"}:
            code = line[1:]
            metadata = var_map.get(code)
            if not metadata:
                if code == clock_code:
                    changes_by_time[current_time]["clock"] = decode_value(line[:1], 1)
                continue
            changes_by_time[current_time][code] = decode_value(line[:1], metadata["width"])
            continue

        if line[0] in {"b", "r"}:
            parts = line.split()
            if len(parts) != 2:
                continue
            token, code = parts
            metadata = var_map.get(code)
            if not metadata:
                if code == clock_code:
                    changes_by_time[current_time]["clock"] = decode_value(token, 1)
                continue
            changes_by_time[current_time][code] = decode_value(token, metadata["width"])

    return var_map, dict(sorted(changes_by_time.items())), clock_code


def infer_clock_period_ps(
    changes_by_time: Dict[int, Dict[str, object]],
    clock_code: Optional[str],
    config: Dict[str, object],
) -> int:
    config_period = config.get("clock_period_ps")
    if isinstance(config_period, int) and config_period > 0:
        return config_period

    if not clock_code:
        raise ValueError("Cannot infer clock period: no clock signal found in VCD")

    rising_edges = []
    previous = 0
    for time_ps, updates in changes_by_time.items():
        if clock_code not in updates:
            continue
        value = updates[clock_code]
        if value == 1 and previous != 1:
            rising_edges.append(time_ps)
            if len(rising_edges) == 2:
                return rising_edges[1] - rising_edges[0]
        previous = 0 if value is None else int(value)

    raise ValueError("Cannot infer clock period from VCD clock signal")


def build_meta(
    var_map: Dict[str, Dict[str, object]],
    config: Dict[str, object],
    clock_period_ps: int,
) -> Dict[str, object]:
    topology = str(config.get("topology", "MESH")).upper()
    if topology not in {"", "MESH"}:
        raise ValueError("This viewer currently supports only MESH topology traces")

    buffer_points = [
        (int(meta["x"]), int(meta["y"]))
        for meta in var_map.values()
        if meta["kind"] in {"buffer_occupancy", "buffer_slot"}
    ]
    link_points = [
        (int(meta["x"]), int(meta["y"]))
        for meta in var_map.values()
        if meta["kind"] in {"link_flit", "free_slots"}
    ]

    points = buffer_points or link_points
    max_x = max((point[0] for point in points), default=0)
    max_y = max((point[1] for point in points), default=0)
    inferred_cols = max_x + 1 if buffer_points else max_x
    inferred_rows = max_y + 1 if buffer_points else max_y

    cols = int(config.get("mesh_dim_x", inferred_cols))
    rows = int(config.get("mesh_dim_y", inferred_rows))

    max_vc = max(
        (int(meta["vc"]) for meta in var_map.values() if "vc" in meta),
        default=-1,
    )
    max_slot = max(
        (int(meta["slot"]) for meta in var_map.values() if "slot" in meta),
        default=-1,
    )

    return {
        "topology": "MESH",
        "mesh_dim_x": cols,
        "mesh_dim_y": rows,
        "clock_period_ps": clock_period_ps,
        "reset_time": int(config.get("reset_time", 0)),
        "n_virtual_channels": int(config.get("n_virtual_channels", max_vc + 1 if max_vc >= 0 else 1)),
        "buffer_depth": max_slot + 1 if max_slot >= 0 else 0,
        "has_buffer_snapshots": max_slot >= 0,
    }


def build_diffs(
    var_map: Dict[str, Dict[str, object]],
    changes_by_time: Dict[int, Dict[str, object]],
    clock_period_ps: int,
) -> Tuple[Dict[int, Dict[str, object]], Dict[int, Dict[str, object]], int]:
    current_sparse: Dict[str, object] = {}
    diffs: Dict[int, Dict[str, object]] = {}
    checkpoints: Dict[int, Dict[str, object]] = {}
    checkpoint_interval = 25
    max_cycle = 0

    for time_ps, updates in changes_by_time.items():
        cycle = int(round(time_ps / clock_period_ps))
        max_cycle = max(max_cycle, cycle)
        cycle_updates: Dict[str, object] = {}

        for code, value in updates.items():
            if code == "clock":
                continue

            meta = var_map.get(code)
            if not meta:
                continue

            kind = meta["kind"]
            if kind == "link_flit":
                key = encode_key("link", meta["x"], meta["y"], meta["direction"], meta["field"])
            elif kind == "free_slots":
                key = encode_key("free", meta["x"], meta["y"], meta["direction"])
            elif kind == "buffer_occupancy":
                key = encode_key("bufocc", meta["x"], meta["y"], meta["direction"], meta["vc"])
            elif kind == "buffer_slot":
                key = encode_key(
                    "bufslot",
                    meta["x"],
                    meta["y"],
                    meta["direction"],
                    meta["vc"],
                    meta["slot"],
                    meta["field"],
                )
            else:
                continue

            normalized = normalize_update(key, value)
            if normalized is None:
                current_sparse.pop(key, None)
                cycle_updates[key] = None
            else:
                current_sparse[key] = normalized
                cycle_updates[key] = normalized

        if cycle_updates:
            diffs.setdefault(cycle, {}).update(cycle_updates)

        if cycle == 0 or cycle % checkpoint_interval == 0:
            checkpoints[cycle] = dict(current_sparse)

    if 0 not in checkpoints:
        checkpoints[0] = {}
    if max_cycle not in checkpoints:
        checkpoints[max_cycle] = dict(current_sparse)

    return diffs, checkpoints, max_cycle


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Noxim Mesh Trace Viewer</title>
  <style>
    :root {{
      --bg: #f6f2e8;
      --panel: #fffdf8;
      --ink: #1b2327;
      --muted: #60707a;
      --line: #d8cfbf;
      --accent: #165d78;
      --accent-soft: rgba(22, 93, 120, 0.10);
      --hot: #a9243a;
      --warm: #b06a2b;
      --shadow: 0 10px 30px rgba(27, 35, 39, 0.08);
      --mono: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      --sans: "Avenir Next", "Segoe UI", system-ui, sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: var(--sans);
      color: var(--ink);
      background:
        radial-gradient(circle at top right, rgba(22, 93, 120, 0.10), transparent 28%),
        linear-gradient(180deg, #fcf8f0 0%, var(--bg) 100%);
    }}
    .shell {{
      max-width: 1680px;
      margin: 0 auto;
      padding: 22px;
    }}
    .topbar {{
      position: sticky;
      top: 0;
      z-index: 10;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 18px;
      padding: 18px 20px;
      margin-bottom: 18px;
      background: rgba(255, 253, 248, 0.93);
      backdrop-filter: blur(12px);
      border: 1px solid rgba(216, 207, 191, 0.9);
      border-radius: 18px;
      box-shadow: var(--shadow);
    }}
    h1 {{
      margin: 0 0 6px 0;
      font-size: 1.55rem;
      letter-spacing: 0.02em;
    }}
    .subtitle {{
      color: var(--muted);
      line-height: 1.45;
      font-size: 0.94rem;
    }}
    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      justify-content: flex-end;
      align-items: center;
    }}
    button, input[type="number"] {{
      font: inherit;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--ink);
      padding: 10px 13px;
    }}
    button {{
      cursor: pointer;
      font-weight: 600;
    }}
    button:hover {{
      border-color: var(--accent);
      color: var(--accent);
    }}
    input[type="range"] {{
      width: 280px;
      accent-color: var(--accent);
    }}
    .statusline {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      margin-bottom: 18px;
      color: var(--muted);
      font-size: 0.93rem;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(22, 93, 120, 0.08);
      color: var(--accent);
      font-weight: 700;
    }}
    .badge.warn {{
      background: rgba(176, 106, 43, 0.12);
      color: var(--warm);
    }}
    .content {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 380px;
      gap: 20px;
      align-items: start;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    .panel-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(22, 93, 120, 0.04), transparent);
    }}
    .panel-head h2 {{
      margin: 0;
      font-size: 1rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .panel-meta {{
      color: var(--muted);
      font-size: 0.82rem;
    }}
    .hint {{
      color: var(--muted);
      font-size: 0.88rem;
      padding: 14px 18px 0 18px;
    }}
    .mesh-grid {{
      display: grid;
      gap: 16px;
      padding: 18px;
    }}
    .tile-card {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: #fffefa;
      padding: 12px;
      cursor: pointer;
      transition: transform 120ms ease, border-color 120ms ease, box-shadow 120ms ease;
    }}
    .tile-card:hover, .tile-card.selected {{
      transform: translateY(-2px);
      border-color: var(--accent);
      box-shadow: 0 12px 24px rgba(22, 93, 120, 0.12);
    }}
    .tile-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
      font-weight: 700;
    }}
    .tile-sub {{
      color: var(--muted);
      font-size: 0.8rem;
      font-weight: 600;
    }}
    .tile-layout {{
      display: grid;
      grid-template-columns: 1fr 1.18fr 1fr;
      grid-template-areas:
        ". north ."
        "west center east"
        ". south .";
      gap: 8px;
      align-items: stretch;
    }}
    .direction-box {{
      border: 1px solid rgba(216, 207, 191, 0.85);
      border-radius: 12px;
      background: rgba(246, 242, 232, 0.72);
      padding: 8px;
      min-height: 88px;
    }}
    .direction-box.north {{ grid-area: north; }}
    .direction-box.east {{ grid-area: east; }}
    .direction-box.south {{ grid-area: south; }}
    .direction-box.west {{ grid-area: west; }}
    .direction-box.active {{
      border-color: rgba(22, 93, 120, 0.42);
      background: rgba(22, 93, 120, 0.08);
    }}
    .direction-box.has-flits {{
      border-color: rgba(169, 36, 58, 0.38);
      background: rgba(169, 36, 58, 0.05);
    }}
    .direction-name {{
      margin-bottom: 5px;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 800;
    }}
    .direction-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 6px;
      font-family: var(--mono);
      font-size: 0.72rem;
    }}
    .pill {{
      padding: 3px 6px;
      border-radius: 999px;
      background: rgba(27, 35, 39, 0.06);
    }}
    .direction-body {{
      font-family: var(--mono);
      font-size: 0.73rem;
      line-height: 1.38;
      color: var(--ink);
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .center-box {{
      grid-area: center;
      border: 1px solid rgba(216, 207, 191, 0.85);
      border-radius: 12px;
      background: linear-gradient(180deg, rgba(22, 93, 120, 0.08), rgba(22, 93, 120, 0.02));
      padding: 10px;
      display: flex;
      flex-direction: column;
      justify-content: center;
      gap: 6px;
      text-align: center;
    }}
    .center-title {{
      font-size: 0.98rem;
      font-weight: 800;
      letter-spacing: 0.02em;
    }}
    .center-meta {{
      color: var(--muted);
      font-family: var(--mono);
      font-size: 0.78rem;
    }}
    .detail-body {{
      padding: 18px;
      font-family: var(--mono);
      font-size: 0.8rem;
      line-height: 1.48;
      white-space: pre-wrap;
      overflow: auto;
      min-height: 320px;
    }}
    .detail-title {{
      font-family: var(--sans);
      font-size: 1rem;
      font-weight: 800;
      margin-bottom: 10px;
    }}
    .detail-section {{
      margin-top: 14px;
      padding-top: 14px;
      border-top: 1px dashed rgba(216, 207, 191, 0.9);
    }}
    @media (max-width: 1200px) {{
      .content {{
        grid-template-columns: 1fr;
      }}
      .controls {{
        justify-content: flex-start;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <div class="topbar">
      <div>
        <h1>Noxim Mesh Trace Viewer</h1>
        <div class="subtitle">
          Mesh-only cycle viewer centered on router buffer contents and link flits.
          The viewer starts at the end of reset, but reset cycles remain accessible.
        </div>
      </div>
      <div class="controls">
        <button id="prevBtn">Previous</button>
        <button id="nextBtn">Next</button>
        <button id="resetStartBtn">Reset start</button>
        <button id="postResetBtn">Post-reset</button>
        <input id="gotoInput" type="number" min="0" step="1">
        <button id="gotoBtn">Go to cycle</button>
        <input id="cycleSlider" type="range" min="0" step="1">
      </div>
    </div>

    <div class="statusline">
      <span class="badge" id="cycleBadge"></span>
      <span class="badge" id="phaseBadge"></span>
      <span class="badge" id="resetBadge"></span>
      <span class="badge" id="meshBadge"></span>
      <span class="badge" id="traceBadge"></span>
    </div>

    <div class="content">
      <div class="panel">
        <div class="panel-head">
          <h2>Mesh State</h2>
          <div class="panel-meta" id="meshCaption"></div>
        </div>
        <div class="hint">
          Click a tile to keep its details pinned while you move through cycles.
        </div>
        <div id="meshGrid" class="mesh-grid"></div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <h2>Selected Tile</h2>
          <div class="panel-meta">Selection persists across cycle changes</div>
        </div>
        <div id="detailBody" class="detail-body">No tile selected yet.</div>
      </div>
    </div>
  </div>

  <script>
    const DATA = __DATA__;

    function key(parts) {{
      return parts.join("|");
    }}

    function defaultValueFor(_encodedKey) {{
      return 0;
    }}

    function applyUpdate(state, encodedKey, value) {{
      if (value === null || value === undefined || value === defaultValueFor(encodedKey)) {{
        delete state[encodedKey];
      }} else {{
        state[encodedKey] = value;
      }}
    }}

    function nearestCheckpoint(targetCycle) {{
      let best = DATA.checkpoint_cycles[0];
      for (const cycle of DATA.checkpoint_cycles) {{
        if (cycle > targetCycle) {{
          break;
        }}
        best = cycle;
      }}
      return best;
    }}

    function materializeCycle(targetCycle) {{
      const checkpointCycle = nearestCheckpoint(targetCycle);
      const state = Object.assign({{}}, DATA.checkpoints[String(checkpointCycle)] || {{}});
      for (let cycle = checkpointCycle + 1; cycle <= targetCycle; cycle += 1) {{
        const updates = DATA.diffs[String(cycle)];
        if (!updates) {{
          continue;
        }}
        for (const [encodedKey, value] of Object.entries(updates)) {{
          applyUpdate(state, encodedKey, value);
        }}
      }}
      return state;
    }}

    function readValue(state, parts, fallback = 0) {{
      const encoded = key(parts);
      return Object.prototype.hasOwnProperty.call(state, encoded) ? state[encoded] : fallback;
    }}

    function signalRef(x, y, direction) {{
      if (direction === "north") return [x, y, "north"];
      if (direction === "west") return [x, y, "west"];
      if (direction === "east") return [x + 1, y, "east"];
      if (direction === "south") return [x, y + 1, "south"];
      return [x, y, direction];
    }}

    function flitTypeLabel(value) {{
      if (value === 0) return "H";
      if (value === 1) return "B";
      if (value === 2) return "T";
      return "?";
    }}

    function freeSlotsLabel(value) {{
      return value < 0 ? "edge" : String(value);
    }}

    function summarizeFlitFields(fields) {{
      const relay = fields.hub_relay_node;
      let summary =
        `${{flitTypeLabel(fields.flit_type)}} ` +
        `${{fields.src_id}}→${{fields.dst_id}} vc${{fields.vc_id}} ` +
        `#${{fields.sequence_no}}/${{fields.sequence_length}} hop${{fields.hop_no}}`;
      if (relay && relay !== -1) {{
        summary += ` relay=${{relay}}`;
      }}
      return summary;
    }}

    function readFlit(state, baseParts) {{
      const fields = {{}};
      let seen = false;
      for (const field of DATA.flit_fields) {{
        const value = readValue(state, [...baseParts, field], 0);
        fields[field] = value;
        if (value) {{
          seen = true;
        }}
      }}
      return seen ? fields : null;
    }}

    function readDirectionState(state, x, y, direction) {{
      const ref = signalRef(x, y, direction);
      const linkFlit = readFlit(state, ["link", ...ref]);
      const freeSlots = readValue(state, ["free", ...ref], 0);
      const vcs = [];

      for (let vc = 0; vc < DATA.meta.n_virtual_channels; vc += 1) {{
        const occupancy = readValue(state, ["bufocc", x, y, direction, vc], 0);
        const slots = [];
        for (let slot = 0; slot < occupancy; slot += 1) {{
          const flit = readFlit(state, ["bufslot", x, y, direction, vc, slot]);
          if (flit) {{
            slots.push(flit);
          }}
        }}
        if (occupancy > 0 || slots.length > 0) {{
          vcs.push({{ vc, occupancy, slots }});
        }}
      }}

      return {{
        direction,
        freeSlots,
        linkFlit,
        vcs,
        active: Boolean(linkFlit) || vcs.length > 0,
        hasFlits: Boolean(linkFlit) || vcs.some((entry) => entry.occupancy > 0)
      }};
    }}

    function tileState(state, x, y) {{
      const directions = ["north", "west", "east", "south"];
      const ports = directions.map((direction) => readDirectionState(state, x, y, direction));
      const totalBuffered = ports.reduce(
        (sum, port) => sum + port.vcs.reduce((acc, vcEntry) => acc + vcEntry.occupancy, 0),
        0
      );
      return {{
        x,
        y,
        id: y * DATA.meta.mesh_dim_x + x,
        ports,
        totalBuffered
      }};
    }}

    function shortDirectionText(port) {{
      const parts = [];
      if (port.freeSlots < 0) {{
        parts.push("mesh edge");
      }}
      if (port.linkFlit) {{
        parts.push(`link ${summarizeFlitFields(port.linkFlit)}`);
      }}
      if (port.vcs.length) {{
        for (const entry of port.vcs) {{
          const slotText = entry.slots.map((flit) => summarizeFlitFields(flit)).join(" | ");
          parts.push(`VC${{entry.vc}} [${{entry.occupancy}}]: ${{slotText}}`);
        }}
      }}
      if (!parts.length) {{
        parts.push("buffer empty");
      }}
      return parts.join("\\n");
    }}

    function renderDirectionBox(port) {{
      const el = document.createElement("div");
      el.className = `direction-box ${{port.direction}}`;
      if (port.active) {{
        el.classList.add("active");
      }}
      if (port.hasFlits) {{
        el.classList.add("has-flits");
      }}

      const metaBits = [];
      metaBits.push(`<span class="pill">free=${{freeSlotsLabel(port.freeSlots)}}</span>`);
      const buffered = port.vcs.reduce((sum, entry) => sum + entry.occupancy, 0);
      metaBits.push(`<span class="pill">buf=${{buffered}}</span>`);

      el.innerHTML = `
        <div class="direction-name">${{port.direction}}</div>
        <div class="direction-meta">${{metaBits.join("")}}</div>
        <div class="direction-body">${{shortDirectionText(port)}}</div>
      `;

      return el;
    }}

    function selectionText(tile, cycle) {{
      const lines = [];
      lines.push(`Cycle: ${{cycle}}`);
      lines.push(`Tile: (${{tile.x}},${{tile.y}})`);
      lines.push(`Tile id: ${{tile.id}}`);
      lines.push(`Buffered flits: ${{tile.totalBuffered}}`);

      for (const port of tile.ports) {{
        lines.push("");
        lines.push(`${{port.direction.toUpperCase()}}`);
        lines.push(`  free slots on link: ${{freeSlotsLabel(port.freeSlots)}}`);
        if (port.linkFlit) {{
          lines.push(`  link flit: ${{summarizeFlitFields(port.linkFlit)}}`);
        }} else {{
          lines.push("  link flit: none");
        }}

        if (!port.vcs.length) {{
          lines.push("  buffers: empty");
          continue;
        }}

        lines.push("  buffers:");
        for (const entry of port.vcs) {{
          lines.push(`    VC${{entry.vc}} occupancy=${{entry.occupancy}}`);
          for (let slot = 0; slot < entry.slots.length; slot += 1) {{
            lines.push(`      slot${{slot}}: ${{summarizeFlitFields(entry.slots[slot])}}`);
          }}
        }}
      }}

      return lines.join("\\n");
    }}

    function renderSelection(state, cycle) {{
      const detailBody = document.getElementById("detailBody");
      if (!selectedTile) {{
        detailBody.textContent = "No tile selected yet.";
        return;
      }}

      const tile = tileState(state, selectedTile.x, selectedTile.y);
      detailBody.textContent = selectionText(tile, cycle);
    }}

    function renderMesh(state, cycle) {{
      const grid = document.getElementById("meshGrid");
      grid.innerHTML = "";
      grid.style.gridTemplateColumns = `repeat(${{DATA.meta.mesh_dim_x}}, minmax(255px, 1fr))`;
      document.getElementById("meshCaption").textContent =
        `${{DATA.meta.mesh_dim_x}}×${{DATA.meta.mesh_dim_y}} mesh, ` +
        `${{DATA.meta.n_virtual_channels}} VC(s), ` +
        `${{DATA.meta.buffer_depth}} traced buffer slot(s)`;

      for (let y = 0; y < DATA.meta.mesh_dim_y; y += 1) {{
        for (let x = 0; x < DATA.meta.mesh_dim_x; x += 1) {{
          const tile = tileState(state, x, y);
          const card = document.createElement("div");
          card.className = "tile-card";
          card.setAttribute("data-tile", `${{x}}-${{y}}`);
          if (selectedTile && selectedTile.x === x && selectedTile.y === y) {{
            card.classList.add("selected");
          }}

          card.innerHTML = `
            <div class="tile-head">
              <div>Tile (${{x}},${{y}})</div>
              <div class="tile-sub">id=${{tile.id}} buffered=${{tile.totalBuffered}}</div>
            </div>
            <div class="tile-layout">
              <div class="center-box">
                <div class="center-title">router</div>
                <div class="center-meta">cycle ${{cycle}}</div>
                <div class="center-meta">buffered flits: ${{tile.totalBuffered}}</div>
              </div>
            </div>
          `;

          const layout = card.querySelector(".tile-layout");
          for (const port of tile.ports) {{
            layout.appendChild(renderDirectionBox(port));
          }}

          card.addEventListener("click", () => {{
            selectedTile = {{ x, y }};
            render(currentCycle);
          }});

          grid.appendChild(card);
        }}
      }}
    }}

    function updateStatus(cycle) {{
      const resetTime = DATA.meta.reset_time || 0;
      const phase = cycle < resetTime ? "reset" : "post-reset";
      document.getElementById("cycleBadge").textContent = `Cycle ${{cycle}} / ${{DATA.max_cycle}}`;
      document.getElementById("phaseBadge").textContent = `Phase: ${{phase}}`;
      document.getElementById("resetBadge").textContent = `Reset window: 0..${{Math.max(resetTime - 1, 0)}}`;
      document.getElementById("meshBadge").textContent =
        `Mesh: ${{DATA.meta.mesh_dim_x}}×${{DATA.meta.mesh_dim_y}}`;
      document.getElementById("traceBadge").textContent = DATA.meta.has_buffer_snapshots
        ? "Buffer snapshots traced"
        : "No buffer snapshots in trace";

      document.getElementById("cycleSlider").value = cycle;
      document.getElementById("gotoInput").value = cycle;
    }}

    let currentCycle = Math.min(DATA.max_cycle, Math.max(0, DATA.meta.reset_time || 0));
    let currentState = materializeCycle(currentCycle);
    let selectedTile = null;

    function render(cycle) {{
      currentCycle = Math.max(0, Math.min(DATA.max_cycle, cycle));
      currentState = materializeCycle(currentCycle);
      updateStatus(currentCycle);
      renderMesh(currentState, currentCycle);
      renderSelection(currentState, currentCycle);
    }}

    document.getElementById("cycleSlider").max = DATA.max_cycle;
    document.getElementById("gotoInput").max = DATA.max_cycle;
    document.getElementById("prevBtn").addEventListener("click", () => render(currentCycle - 1));
    document.getElementById("nextBtn").addEventListener("click", () => render(currentCycle + 1));
    document.getElementById("resetStartBtn").addEventListener("click", () => render(0));
    document.getElementById("postResetBtn").addEventListener("click", () => render(DATA.meta.reset_time || 0));
    document.getElementById("gotoBtn").addEventListener(
      "click",
      () => render(parseInt(document.getElementById("gotoInput").value || "0", 10))
    );
    document.getElementById("cycleSlider").addEventListener(
      "input",
      (event) => render(parseInt(event.target.value, 10))
    );

    render(currentCycle);
  </script>
</body>
</html>
"""


def write_html(output_path: str, data: Dict[str, object]) -> None:
    rendered = (
        HTML_TEMPLATE.replace("{{", "{")
        .replace("}}", "}")
        .replace("__DATA__", json.dumps(data, separators=(",", ":")))
    )
    Path(output_path).write_text(rendered, encoding="utf-8")


def main() -> int:
    args = parse_args()
    config = read_simple_config(args.config)
    var_map, changes_by_time, clock_code = parse_vcd(args.vcd)
    clock_period_ps = infer_clock_period_ps(changes_by_time, clock_code, config)
    meta = build_meta(var_map, config, clock_period_ps)
    diffs, checkpoints, max_cycle = build_diffs(var_map, changes_by_time, clock_period_ps)

    data = {
        "meta": meta,
        "flit_fields": list(FLIT_FIELDS),
        "max_cycle": max_cycle,
        "diffs": {str(cycle): updates for cycle, updates in diffs.items()},
        "checkpoints": {str(cycle): snapshot for cycle, snapshot in checkpoints.items()},
        "checkpoint_cycles": sorted(checkpoints.keys()),
    }

    write_html(args.output, data)
    print(f"[viewer] Wrote {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"[viewer] Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
