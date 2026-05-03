const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const Environ = std.process.Environ;

const tinycni = @import("tinycni");

var rng: std.Random.DefaultPrng = undefined;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var arena = init.arena;
    const allocator = arena.allocator();

    rng.seed(@truncate(@as(u96, @bitCast(std.Io.Clock.real.now(io).nanoseconds))));

    var buf: [128]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(io, &buf);
    const stdin = try stdin_reader.interface.allocRemaining(allocator, .unlimited);
    const input = try Input.parse(allocator, stdin, init.environ_map);

    const gateway = try std.Io.net.Ip4Address.parse(input.config.gateway, 0);
    const bridge_name = input.config.bridge;

    var host_client = try tinycni.Client.init();
    defer host_client.deinit();

    const netns = try allocator.dupeSentinel(u8, input.netns, 0);
    const netns_fd = linux.open(netns, .{}, 0);
    defer _ = linux.close(@intCast(netns_fd));

    const bridge_index = host_client.ifnameToIndex(bridge_name) catch blk: {
        try host_client.createBridge(bridge_name);
        const bridge_index = try host_client.ifnameToIndex(bridge_name);
        try host_client.upLink(bridge_index);
        try host_client.addIpv4Addr(bridge_index, gateway.bytes);
        try configureNat(io, input.config.subnet, "eth0");
        break :blk bridge_index;
    };

    const host_veth_name = try generateRandomVethName(allocator);
    const peer_veth_name = try generateRandomVethName(allocator);

    try host_client.createVeth(host_veth_name, peer_veth_name);
    const host_veth_index = try host_client.ifnameToIndex(host_veth_name);
    const peer_veth_index = try host_client.ifnameToIndex(peer_veth_name);
    try host_client.moveLinkToNetns(netns_fd, peer_veth_index);

    try host_client.attachToBridge(host_veth_index, bridge_index);
    try host_client.upLink(host_veth_index);

    const n = linux.setns(@intCast(netns_fd), 0);
    if (linux.errno(n) != .SUCCESS) return error.SetnsError;

    var netns_client = try tinycni.Client.init();
    defer netns_client.deinit();

    const netns_veth_index = try netns_client.ifnameToIndex(peer_veth_name);

    try netns_client.renameInterface(netns_veth_index, input.ifname);

    try netns_client.upLink(1); // lo
    try netns_client.upLink(netns_veth_index);

    try netns_client.addIpv4Addr(netns_veth_index, [_]u8{ 10, 0, 0, 2 });

    try netns_client.setDefaultGateway(netns_veth_index, gateway.bytes);
}

fn configureNat(io: std.Io, subnet: []const u8, out: []const u8) !void {
    var proc = try std.process.spawn(io, .{
        .argv = &.{
            "iptables",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            subnet,
            "-o",
            out,
            "-j",
            "MASQUERADE",
        },
    });
    _ = try proc.wait(io);
}

fn generateRandomVethName(allocator: std.mem.Allocator) ![]const u8 {
    const chars = "1234567890abcdefghijklmnopqrstuvvwxyz";
    const prefix = "veth_";
    const rand_len = 6;

    var buf: [4]u8 = undefined;
    rng.fill(buf[0..]);
    var n: u32 = std.mem.readInt(u32, &buf, .native);

    const res = try allocator.alloc(u8, prefix.len + rand_len);
    @memcpy(res.ptr, prefix);
    for (0..rand_len) |i| {
        res[prefix.len + i] = chars[n % chars.len];
        n /= chars.len;
    }

    return res;
}

const Input = struct {
    cmd: Command,
    container_id: []const u8,
    netns: []const u8,
    ifname: []const u8,

    config: Config,

    const Config = struct {
        cniVersion: []const u8,
        name: []const u8,
        type: []const u8,

        bridge: []const u8,
        subnet: []const u8,
        gateway: []const u8,
    };

    const Command = enum {
        add,
        del,

        fn parse(cmd_str: []const u8) !Command {
            const eql = std.mem.eql;
            if (eql(u8, cmd_str, "ADD")) {
                return .add;
            } else if (eql(u8, cmd_str, "DEL")) {
                return .del;
            }
            return error.InvalidCommand;
        }
    };

    fn parse(arena: std.mem.Allocator, stdin: []const u8, env: *const Environ.Map) !Input {
        const err = error.InvalidInput;

        const config = try std.json.parseFromSliceLeaky(Config, arena, stdin, .{});

        const cmd_str = env.get("CNI_COMMAND") orelse {
            log.err("missing CNI_COMMAND", .{});
            return err;
        };
        const cmd = try Command.parse(cmd_str);

        const container_id = env.get("CNI_CONTAINERID") orelse {
            log.err("missing CNI_CONTAINERID", .{});
            return err;
        };

        const netns = env.get("CNI_NETNS") orelse {
            log.err("missing CNI_NETNS", .{});
            return err;
        };

        const ifname = env.get("CNI_IFNAME") orelse {
            log.err("missing CNI_IFNAME", .{});
            return err;
        };

        return .{
            .cmd = cmd,
            .container_id = container_id,
            .netns = netns,
            .ifname = ifname,

            .config = config,
        };
    }
};
