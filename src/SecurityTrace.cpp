/*
 * NoC Sentinel - see SecurityTrace.h for configuration semantics.
 */

#include "SecurityTrace.h"
#include "GlobalParams.h"

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <map>
#include <queue>
#include <vector>
#include <sstream>

using namespace std;

namespace SecurityTrace {

enum SrcPolicy { SRC_ALLOW, SRC_QUARANTINE };
enum DstPolicy { DST_DELIVER, DST_QUARANTINE, DST_REMAP };

struct PacketRec {
    int id, src, logical_dst, actual_dst, size;
    double gen_cycle, entered_cycle;
    string action;
    vector<int> path;
    int mitigation_reroutes, attack_deviations, invalid_hops;
    int flits_delivered, delivered_node;
    double delivered_cycle;
    int flits_dropped, drop_node;
    bool tampered;
    int tamper_node, tamper_new_dst;
};

struct HopRec {
    int packet_id;
    double cycle;
    int router, out_dir, next_node, xy_dir, xy_next;
    string deviation;
};

static bool g_init = false;
static int g_mal = -1;
static string g_attack;
static bool g_mitigate_req = false;
static bool g_mitigate = false;
static SrcPolicy g_src = SRC_QUARANTINE;
static DstPolicy g_dst = DST_QUARANTINE;
static int g_backup = -1;
static string g_prefix;
static bool g_decouple = false;
static unsigned int g_rng = 2463534242u;
static int g_next_id = 0;

static map<int, PacketRec> g_packets;
static vector<HopRec> g_hops;
static map<int, vector<int> > g_dist_cache;

static int nodes() { return GlobalParams::mesh_dim_x * GlobalParams::mesh_dim_y; }

static string envs(const char *k, const string &def)
{
    const char *v = getenv(k);
    return (v && *v) ? string(v) : def;
}

static const char *srcName(SrcPolicy p) { return p == SRC_ALLOW ? "ALLOW" : "QUARANTINE"; }
static const char *dstName(DstPolicy p)
{
    return p == DST_DELIVER ? "DELIVER" : (p == DST_REMAP ? "REMAP" : "QUARANTINE");
}
static const char *dirName(int d)
{
    switch (d) {
    case DIRECTION_NORTH: return "N";
    case DIRECTION_EAST:  return "E";
    case DIRECTION_SOUTH: return "S";
    case DIRECTION_WEST:  return "W";
    case DIRECTION_LOCAL: return "L";
    default: return "?";
    }
}

static void fail(const string &msg)
{
    cerr << "SENTINEL_ERROR: " << msg << endl;
    exit(2);
}

void init()
{
    if (g_init) return;
    g_init = true;

    g_mal = atoi(envs("NOXIM_MAL_NODE", "-1").c_str());
    g_attack = envs("NOXIM_ATTACK", "NONE");
    g_mitigate_req = atoi(envs("NOXIM_MITIGATE", "0").c_str()) != 0;
    g_prefix = envs("NOXIM_TRACE_PREFIX", "");
    g_decouple = atoi(envs("NOXIM_DECOUPLE_RNG", "0").c_str()) != 0;
    g_rng ^= (unsigned int) GlobalParams::rnd_generator_seed * 2654435761u;
    if (g_rng == 0) g_rng = 1;

    string sp = envs("NOXIM_SRC_POLICY", "QUARANTINE");
    if (sp == "ALLOW") g_src = SRC_ALLOW;
    else if (sp == "QUARANTINE") g_src = SRC_QUARANTINE;
    else fail("NOXIM_SRC_POLICY must be ALLOW or QUARANTINE, got " + sp);

    string dp = envs("NOXIM_DST_POLICY", "QUARANTINE");
    if (dp == "DELIVER") g_dst = DST_DELIVER;
    else if (dp == "QUARANTINE") g_dst = DST_QUARANTINE;
    else if (dp == "REMAP") g_dst = DST_REMAP;
    else fail("NOXIM_DST_POLICY must be DELIVER, QUARANTINE or REMAP, got " + dp);

    g_backup = atoi(envs("NOXIM_BACKUP_NODE", "-1").c_str());

    bool mesh = (GlobalParams::topology == TOPOLOGY_MESH);
    if (g_mal >= 0 && mesh && g_mal >= nodes()) {
        ostringstream o;
        o << "NOXIM_MAL_NODE=" << g_mal << " is outside the " << GlobalParams::mesh_dim_x
          << "x" << GlobalParams::mesh_dim_y << " mesh (valid 0.." << nodes() - 1 << ")";
        fail(o.str());
    }

    if (g_mitigate_req) {
        if (!mesh) fail("mitigation is implemented for MESH topology only");
        if (g_mal < 0) {
            cout << "SENTINEL_WARNING: NOXIM_MITIGATE=1 but no NOXIM_MAL_NODE; mitigation inactive" << endl;
        } else {
            g_mitigate = true;
        }
        if (GlobalParams::routing_algorithm != "XY")
            cout << "SENTINEL_WARNING: deviation labels are relative to XY; routing="
                 << GlobalParams::routing_algorithm << endl;
    }

    if (g_mitigate && g_dst == DST_REMAP) {
        if (g_backup < 0 || g_backup >= nodes())
            fail("NOXIM_DST_POLICY=REMAP requires a valid NOXIM_BACKUP_NODE (no automatic choice)");
        if (g_backup == g_mal)
            fail("NOXIM_BACKUP_NODE must differ from NOXIM_MAL_NODE");
    }

    cout << "SENTINEL_CONFIG mal_node=" << g_mal << " attack=" << g_attack
         << " mitigation=" << (g_mitigate ? 1 : 0)
         << " src_policy=" << srcName(g_src) << " dst_policy=" << dstName(g_dst)
         << " backup_node=" << g_backup << " decouple_rng=" << (g_decouple ? 1 : 0)
         << " trace_prefix=" << (g_prefix.empty() ? "(none)" : g_prefix) << endl;
}

bool mitigationActive() { return g_mitigate; }
int malNode() { return g_mal; }
bool decoupleRng() { return g_decouple; }

unsigned int localRand()
{
    // xorshift32 - private stream, does not disturb rand()
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

int neighborOf(int node, int dir)
{
    int X = GlobalParams::mesh_dim_x, Y = GlobalParams::mesh_dim_y;
    if (node < 0 || node >= X * Y) return -1;
    int x = node % X, y = node / X;
    switch (dir) {
    case DIRECTION_NORTH: y--; break;
    case DIRECTION_SOUTH: y++; break;
    case DIRECTION_EAST:  x++; break;
    case DIRECTION_WEST:  x--; break;
    case DIRECTION_LOCAL: return node;
    default: return -1;
    }
    if (x < 0 || y < 0 || x >= X || y >= Y) return -1;
    return y * X + x;
}

int xyDirection(int cur, int dst)
{
    int X = GlobalParams::mesh_dim_x;
    int cx = cur % X, cy = cur / X, dx = dst % X, dy = dst / X;
    if (dx > cx) return DIRECTION_EAST;
    if (dx < cx) return DIRECTION_WEST;
    if (dy > cy) return DIRECTION_SOUTH;
    if (dy < cy) return DIRECTION_NORTH;
    return DIRECTION_LOCAL;
}

// BFS hop distance to dst over the mesh with the compromised node removed.
// The compromised node is only kept when it is itself the destination.
static const vector<int> &distFor(int dst)
{
    map<int, vector<int> >::iterator it = g_dist_cache.find(dst);
    if (it != g_dist_cache.end()) return it->second;

    vector<int> dist(nodes(), -1);
    int excluded = (g_mal != dst) ? g_mal : -1;
    queue<int> q;
    dist[dst] = 0;
    q.push(dst);
    const int dirs[4] = { DIRECTION_NORTH, DIRECTION_EAST, DIRECTION_SOUTH, DIRECTION_WEST };
    while (!q.empty()) {
        int u = q.front(); q.pop();
        for (int k = 0; k < 4; k++) {
            int v = neighborOf(u, dirs[k]);
            if (v < 0 || v == excluded || dist[v] >= 0) continue;
            dist[v] = dist[u] + 1;
            q.push(v);
        }
    }
    return g_dist_cache[dst] = dist;
}

int safeRoute(int cur, int dst)
{
    if (!g_mitigate) return -1;
    if (cur == dst) return DIRECTION_LOCAL;
    if (cur == g_mal) return -1;          // compromised router: not trusted to mitigate
    const vector<int> &d = distFor(dst);
    if (d[cur] <= 0) return -1;           // unreachable without the compromised node
    int excluded = (g_mal != dst) ? g_mal : -1;
    int xy = xyDirection(cur, dst);
    int chosen = -1;
    const int dirs[4] = { DIRECTION_NORTH, DIRECTION_EAST, DIRECTION_SOUTH, DIRECTION_WEST };
    for (int k = 0; k < 4; k++) {
        int v = neighborOf(cur, dirs[k]);
        if (v < 0 || v == excluded) continue;
        if (d[v] == d[cur] - 1) {         // strictly decreasing distance => loop-free
            if (dirs[k] == xy) return xy; // keep XY whenever it is a safe shortest move
            if (chosen < 0) chosen = dirs[k];
        }
    }
    return chosen;
}

bool onPacketGenerated(Packet &p, double now)
{
    p.packet_id = g_next_id++;
    p.logical_dst_id = p.dst_id;

    PacketRec r;
    r.id = p.packet_id;
    r.src = p.src_id;
    r.logical_dst = p.dst_id;
    r.size = p.size;
    r.gen_cycle = now;
    r.entered_cycle = -1;
    r.action = "INJECTED";
    r.mitigation_reroutes = r.attack_deviations = r.invalid_hops = 0;
    r.flits_delivered = 0;
    r.delivered_node = -1;
    r.delivered_cycle = -1;
    r.flits_dropped = 0;
    r.drop_node = -1;
    r.tampered = false;
    r.tamper_node = r.tamper_new_dst = -1;

    bool inject = true;
    if (g_mitigate) {
        if (p.src_id == g_mal && g_src == SRC_QUARANTINE) {
            r.action = "QUARANTINED_SRC";
            inject = false;
        } else if (p.dst_id == g_mal) {
            if (g_dst == DST_QUARANTINE) {
                r.action = "QUARANTINED_DST";
                inject = false;
            } else if (g_dst == DST_REMAP) {
                if (g_backup == p.src_id) {
                    r.action = "QUARANTINED_DST_BACKUP_IS_SRC";
                    inject = false;
                } else {
                    p.dst_id = g_backup;
                    r.action = "REMAPPED";
                }
            }
        }
    }
    r.actual_dst = p.dst_id;
    r.path.push_back(p.src_id);
    g_packets[r.id] = r;
    return inject;
}

static PacketRec *rec(const Flit &f)
{
    if (f.packet_id < 0) return 0;
    map<int, PacketRec>::iterator it = g_packets.find(f.packet_id);
    return it == g_packets.end() ? 0 : &it->second;
}

void onHeadEnteredNetwork(const Flit &f, int, double now)
{
    PacketRec *r = rec(f);
    if (r && f.flit_type == FLIT_TYPE_HEAD && r->entered_cycle < 0) r->entered_cycle = now;
}

void onForward(const Flit &f, int router, int out_dir, double now)
{
    if (f.flit_type != FLIT_TYPE_HEAD || out_dir == DIRECTION_LOCAL) return;
    PacketRec *r = rec(f);
    if (!r) return;
    HopRec h;
    h.packet_id = f.packet_id;
    h.cycle = now;
    h.router = router;
    h.out_dir = out_dir;
    h.next_node = neighborOf(router, out_dir);
    h.xy_dir = xyDirection(router, f.dst_id);
    h.xy_next = neighborOf(router, h.xy_dir);
    if (out_dir == h.xy_dir) h.deviation = "NONE";
    else if (router == g_mal) { h.deviation = "ATTACK"; r->attack_deviations++; }
    else if (g_mitigate) { h.deviation = "MITIGATION"; r->mitigation_reroutes++; }
    else h.deviation = "OTHER";
    if (h.next_node < 0) r->invalid_hops++;
    r->path.push_back(h.next_node);
    g_hops.push_back(h);
}

void onLocalConsume(const Flit &f, int router, double now)
{
    PacketRec *r = rec(f);
    if (!r) return;
    r->flits_delivered++;
    if (r->delivered_node < 0) r->delivered_node = router;
    if (r->flits_delivered >= r->size) r->delivered_cycle = now;
}

void onAttackDrop(const Flit &f, int router, double)
{
    PacketRec *r = rec(f);
    if (!r) return;
    r->flits_dropped++;
    if (r->drop_node < 0) r->drop_node = router;
}

void onTamper(const Flit &f, int router, int, int new_dst, double)
{
    PacketRec *r = rec(f);
    if (!r || f.flit_type != FLIT_TYPE_HEAD) return;
    r->tampered = true;
    r->tamper_node = router;
    r->tamper_new_dst = new_dst;
}

static string outcomeOf(const PacketRec &r)
{
    if (r.action.compare(0, 11, "QUARANTINED") == 0) return r.action;
    if (r.delivered_node >= 0 && r.flits_delivered >= r.size)
        return r.delivered_node == r.actual_dst ? "DELIVERED" : "MISDELIVERED";
    if (r.flits_dropped > 0) return "DROPPED";
    if (r.flits_delivered > 0) return "PARTIAL";
    if (r.entered_cycle < 0) return "QUEUED_AT_SOURCE";
    return "IN_FLIGHT";
}

void exportAll()
{
    double warm = GlobalParams::reset_time + GlobalParams::stats_warm_up_time;
    map<string, int> counts;
    int generated = 0, reroutes = 0;
    for (map<int, PacketRec>::iterator it = g_packets.begin(); it != g_packets.end(); ++it) {
        generated++;
        counts[outcomeOf(it->second)]++;
        if (it->second.action == "REMAPPED") counts["(remapped)"]++;
        reroutes += it->second.mitigation_reroutes;
    }
    cout << "SENTINEL_SUMMARY generated=" << generated;
    for (map<string, int>::iterator it = counts.begin(); it != counts.end(); ++it)
        cout << " " << it->first << "=" << it->second;
    cout << " mitigation_reroute_hops=" << reroutes << endl;

    if (g_prefix.empty()) return;

    ofstream pf((g_prefix + "_packets.csv").c_str());
    pf << "packet_id,src,logical_dst,actual_dst,remapped,gen_cycle,after_warmup,size_flits,"
          "policy_action,entered_cycle,path,hop_count,mitigation_reroutes,attack_deviations,"
          "invalid_hops,flits_delivered,delivered_node,delivered_cycle,latency_cycles,"
          "flits_dropped,drop_node,tampered,tamper_new_dst,outcome,attack_mode,mal_node,mitigation\n";
    for (map<int, PacketRec>::iterator it = g_packets.begin(); it != g_packets.end(); ++it) {
        const PacketRec &r = it->second;
        ostringstream path;
        for (size_t i = 0; i < r.path.size(); i++) path << (i ? ">" : "") << r.path[i];
        double lat = (r.delivered_cycle >= 0) ? r.delivered_cycle - r.gen_cycle : -1;
        pf << r.id << "," << r.src << "," << r.logical_dst << "," << r.actual_dst << ","
           << (r.action == "REMAPPED" ? 1 : 0) << "," << r.gen_cycle << ","
           << (r.gen_cycle >= warm ? 1 : 0) << "," << r.size << "," << r.action << ","
           << r.entered_cycle << "," << path.str() << "," << (r.path.size() - 1) << ","
           << r.mitigation_reroutes << "," << r.attack_deviations << "," << r.invalid_hops << ","
           << r.flits_delivered << "," << r.delivered_node << "," << r.delivered_cycle << ","
           << lat << "," << r.flits_dropped << "," << r.drop_node << ","
           << (r.tampered ? 1 : 0) << "," << r.tamper_new_dst << "," << outcomeOf(r) << ","
           << g_attack << "," << g_mal << "," << (g_mitigate ? 1 : 0) << "\n";
    }

    ofstream hf((g_prefix + "_hops.csv").c_str());
    hf << "packet_id,cycle,router,out_dir,next_node,xy_dir,xy_next,deviation\n";
    for (size_t i = 0; i < g_hops.size(); i++) {
        const HopRec &h = g_hops[i];
        hf << h.packet_id << "," << h.cycle << "," << h.router << "," << dirName(h.out_dir) << ","
           << h.next_node << "," << dirName(h.xy_dir) << "," << h.xy_next << "," << h.deviation << "\n";
    }

    ofstream cf((g_prefix + "_config.csv").c_str());
    cf << "key,value\n"
       << "mal_node," << g_mal << "\n"
       << "attack," << g_attack << "\n"
       << "mitigation," << (g_mitigate ? 1 : 0) << "\n"
       << "src_policy," << srcName(g_src) << "\n"
       << "dst_policy," << dstName(g_dst) << "\n"
       << "backup_node," << g_backup << "\n"
       << "decouple_rng," << (g_decouple ? 1 : 0) << "\n"
       << "mesh_dim_x," << GlobalParams::mesh_dim_x << "\n"
       << "mesh_dim_y," << GlobalParams::mesh_dim_y << "\n"
       << "routing," << GlobalParams::routing_algorithm << "\n"
       << "seed," << GlobalParams::rnd_generator_seed << "\n"
       << "reset_cycles," << GlobalParams::reset_time << "\n"
       << "warmup_cycles," << GlobalParams::stats_warm_up_time << "\n"
       << "sim_cycles," << GlobalParams::simulation_time << "\n";
}

}
