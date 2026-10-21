#!/usr/bin/env python3
"""Apply NoC Sentinel patches to Noxim sources. Aborts if any anchor is not found
exactly once, so nothing is silently mis-applied. Run from repository root."""
import re
import sys
from pathlib import Path

def patch(path, edits):
    p = Path(path)
    src = p.read_text()
    if "SecurityTrace" in src:
        print(f"[skip] {path}: already patched")
        return
    for desc, pattern, repl in edits:
        new, n = re.subn(pattern, repl, src, count=0)
        if n != 1:
            sys.exit(f"[FAIL] {path}: anchor '{desc}' matched {n} times (expected 1)")
        src = new
        print(f"[ok]   {path}: {desc}")
    p.write_text(src)

NOW = "sc_time_stamp().to_double() / GlobalParams::clock_period_ps"

patch("src/DataStructs.h", [
    ("Packet default ctor", r"    Packet\(\) \{ \}",
     "    int packet_id;      // NoC Sentinel: unique packet id (-1 = unassigned)\n"
     "    int logical_dst_id; // NoC Sentinel: destination before any remap\n\n"
     "    Packet() : packet_id(-1), logical_dst_id(-1) { }"),
    ("Packet::make init", r"(\tflit_left = sz;\n)",
     r"\1\tpacket_id = -1;\n\tlogical_dst_id = d;\n"),
    ("Flit fields", r"(\n    int hub_relay_node;\n)",
     r"\1    int packet_id = -1;       // NoC Sentinel: unique packet id\n"
     r"    int logical_dst_id = -1;  // NoC Sentinel: destination before any remap\n"),
])

patch("src/ProcessingElement.cpp", [
    ("include", r'(#include "ProcessingElement.h"\n)', r'\1#include "SecurityTrace.h"\n'),
    ("random/table injection", r"if \(canShot\(packet\)\) \{\s*\n(\s*)packet_queue\.push\(packet\);",
     "if (canShot(packet)) {\n\\1if (SecurityTrace::onPacketGenerated(packet, " + NOW + "))\n\\1    packet_queue.push(packet);"),
    ("hardcoded injection",
     r"(packet\.make\(local_id, expected_packet\.dst, vc, now, getRandomSize\(\)\);\s*\n\s*)packet_queue\.push\(packet\);",
     r"\1if (SecurityTrace::onPacketGenerated(packet, now)) packet_queue.push(packet);"),
    ("nextFlit ids", r"(\n    flit\.timestamp = packet\.timestamp;\n)",
     r"\1    flit.packet_id = packet.packet_id;\n    flit.logical_dst_id = packet.logical_dst_id;\n"),
])

patch("src/Router.cpp", [
    ("include", r'(#include "Router.h"\n)', r'\1#include "SecurityTrace.h"\n'),
    ("tamper hook", r"(received_flit\.dst_id =\s*\n\s*\(original_dst \+ 1\) % node_count;\n)",
     r"\1                                SecurityTrace::onTamper(received_flit, local_id, original_dst, received_flit.dst_id, 0);\n"),
    ("drop / entry hook", r"if \(!attack_drop\)\s*\n\s*buffer\[i\]\[vc\]\.Push\(received_flit\);",
     "if (attack_drop)\n"
     "                        SecurityTrace::onAttackDrop(received_flit, local_id, " + NOW + ");\n"
     "                    else {\n"
     "                        if (i == DIRECTION_LOCAL)\n"
     "                            SecurityTrace::onHeadEnteredNetwork(received_flit, local_id, " + NOW + ");\n"
     "                        buffer[i][vc].Push(received_flit);\n"
     "                    }"),
    ("decoupled arbitration RNG", r"int rnd_idx = rand\(\)%reservations\.size\(\);",
     "int rnd_idx = SecurityTrace::decoupleRng()\n"
     "\t\t  ? (reservations.size() == 1 ? 0 : (int)(SecurityTrace::localRand() % reservations.size()))\n"
     "\t\t  : rand()%reservations.size();"),
    ("forward hook", r"(\n(\s*)flit_tx\[o\]\.write\(flit\);\n)",
     "\\1\\2SecurityTrace::onForward(flit, local_id, o, " + NOW + ");\n"),
    ("consume hook", r"(stats\.receivedFlit\(sc_time_stamp\(\)\.to_double\(\) / GlobalParams::clock_period_ps, flit\);\n)",
     "\\1\t\t\t  SecurityTrace::onLocalConsume(flit, local_id, " + NOW + ");\n"),
    ("replace old mitigation block",
     r"(?s)if \(NOXIM_MITIGATE && NOXIM_MAL_NODE >= 0 && !candidate_channels\.empty\(\)\)\n\{.*?\n\}\n(?=\s*power\.selection\(\);)",
     "    // NoC Sentinel avoidance routing. Applied at every healthy router; the\n"
     "    // compromised router itself is untrusted and keeps its (attacked) behaviour.\n"
     "    if (SecurityTrace::mitigationActive() && local_id != SecurityTrace::malNode())\n"
     "    {\n"
     "        int safe = SecurityTrace::safeRoute(local_id, route_data.dst_id);\n"
     "        if (safe >= 0)\n"
     "        {\n"
     "            if (!candidate_channels.empty() && safe != candidate_channels[0] && NOXIM_ATTACK_LOG++ < 20)\n"
     "                cout << \"SENTINEL_HOOK: node \" << local_id << \" dst \" << route_data.dst_id\n"
     "                     << \" dir \" << candidate_channels[0] << \" -> \" << safe\n"
     "                     << \" (avoiding node \" << SecurityTrace::malNode() << \")\" << endl;\n"
     "            candidate_channels.assign(1, safe);\n"
     "        }\n"
     "    }\n"),
    ("decoupled selection RNG", r"(\n(\s*)return selectionFunction\(candidate_channels, route_data\);)",
     "\n\\2if (SecurityTrace::decoupleRng() && candidate_channels.size() == 1)\n"
     "\\2    return candidate_channels[0];\\1"),
])

patch("src/Main.cpp", [
    ("include", r'(#include "Logger.h"\n)', r'\1#include "SecurityTrace.h"\n'),
    ("init", r"(\n(\s*)srand\(GlobalParams::rnd_generator_seed\);)", r"\n\2SecurityTrace::init();\1"),
    ("export", r"(gs\.exportStats\(GlobalParams::stats_format, GlobalParams::stats_file, GlobalParams::detailed\);\n)",
     r"\1    SecurityTrace::exportAll();\n"),
])
print("ALL PATCHES APPLIED")
