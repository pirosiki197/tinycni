const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const Allocator = std.mem.Allocator;

const tinycni = @import("tinycni");
const Client = tinycni.netlink.Client;
const Ipv4Addr = tinycni.net.Ipv4Addr;
const Ipv4Net = tinycni.net.Ipv4Net;

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

    switch (input.cmd) {
        .add => try handleAdd(allocator, io, input),
        .del => try handleDel(allocator, input),
    }
}

fn handleAdd(allocator: Allocator, io: std.Io, input: Input) !void {
    var host_client = try Client.init();
    defer host_client.deinit();

    const netns = try allocator.dupeSentinel(u8, input.netns, 0);
    const netns_fd = linux.open(netns, .{}, 0);
    defer _ = linux.close(@intCast(netns_fd));

    const bridge_name = input.config.bridge;
    const bridge = host_client.getLinkByName(bridge_name) catch blk: {
        try host_client.createBridge(bridge_name);
        const bridge = try host_client.getLinkByName(bridge_name);
        try host_client.upLink(bridge.index);
        try host_client.addIpv4Addr(bridge.index, input.config.gateway.bytes);
        try configureNat(io, try input.config.subnet.string(allocator), "eth0");
        break :blk bridge;
    };

    const host_veth_name = try generateVethName(allocator);
    const peer_veth_name = try generateVethName(allocator);

    try host_client.createVeth(host_veth_name, generateMac(), peer_veth_name, generateMac());
    const host_veth = try host_client.getLinkByName(host_veth_name);
    const peer_veth = try host_client.getLinkByName(peer_veth_name);
    try host_client.moveLinkToNetns(netns_fd, peer_veth.index);

    try host_client.attachToBridge(host_veth.index, bridge.index);
    try host_client.upLink(host_veth.index);

    const n = linux.setns(@intCast(netns_fd), 0);
    if (linux.errno(n) != .SUCCESS) return error.SetnsError;

    var netns_client = try Client.init();
    defer netns_client.deinit();

    const netns_veth = try netns_client.getLinkByName(peer_veth_name);

    try netns_client.renameInterface(netns_veth.index, input.ifname);

    try netns_client.upLink(1); // lo
    try netns_client.upLink(netns_veth.index);

    try netns_client.addIpv4Addr(netns_veth.index, [_]u8{ 10, 0, 0, 2 });

    try netns_client.setDefaultGateway(netns_veth.index, input.config.gateway.bytes);

    const result = Result{
        .cniVersion = "1.0.0",
        .interfaces = &.{
            .{
                .name = host_veth_name,
                .mac = &formatMac(host_veth.mac),
            },
            .{
                .name = input.ifname,
                .mac = &formatMac(peer_veth.mac),
                .sandbox = input.netns,
            },
        },
        .ips = &.{
            .{
                .address = "10.0.0.2/24",
                .gateway = try input.config.gateway.string(allocator),
                .interface = 1,
            },
        },
        .routes = &.{},
        .dns = .{},
    };
    var stdout_writer = std.Io.File.stdout().writer(io, &.{});
    try std.json.fmt(result, .{}).format(&stdout_writer.interface);
}

fn handleDel(allocator: Allocator, input: Input) !void {
    const netns = try allocator.dupeSentinel(u8, input.netns, 0);
    const netns_fd = linux.open(netns, .{}, 0);
    if (linux.errno(netns_fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(netns_fd));

    const n = linux.setns(@intCast(netns_fd), 0);
    if (linux.errno(n) != .SUCCESS) return error.SetnsError;

    var netns_client = try Client.init();
    defer netns_client.deinit();

    const interface = netns_client.getLinkByName(input.ifname) catch return;
    try netns_client.deleteInterface(interface.index);
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

fn generateVethName(allocator: Allocator) ![]const u8 {
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

fn generateMac() [6]u8 {
    var mac: [6]u8 = undefined;
    rng.fill(&mac);
    // unicast & locally administered address
    mac[0] = (mac[0] & 0xFE) | 0x02;
    return mac;
}

fn formatMac(mac: [6]u8) [17]u8 {
    var res: [17]u8 = undefined;
    var i: usize = 0;
    for (mac) |d| {
        res[i] = std.fmt.hex_charset[d >> 4];
        res[i + 1] = std.fmt.hex_charset[d & 15];
        i += 2;
        if (i != res.len) {
            res[i] = ':';
            i += 1;
        }
    }
    return res;
}

const Input = struct {
    cmd: Command,
    container_id: []const u8,
    netns: []const u8,
    ifname: []const u8,

    config: Config,

    const Ip4Address = std.Io.net.Ip4Address;

    const Config = struct {
        cni_version: []const u8,
        name: []const u8,
        type: []const u8,

        bridge: []const u8,
        subnet: Ipv4Net,
        gateway: Ipv4Addr,
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

    fn parse(arena: Allocator, stdin: []const u8, env: *const std.process.Environ.Map) !Input {
        const StdinJson = struct {
            cniVersion: []const u8,
            name: []const u8,
            type: []const u8,

            bridge: []const u8,
            subnet: []const u8,
            gateway: []const u8,
        };

        const err = error.InvalidInput;

        const raw_config = try std.json.parseFromSliceLeaky(StdinJson, arena, stdin, .{});
        const config = Config{
            .cni_version = raw_config.cniVersion,
            .name = raw_config.name,
            .type = raw_config.type,
            .bridge = raw_config.bridge,
            .subnet = try .parse(raw_config.subnet),
            .gateway = try .parse(raw_config.gateway),
        };

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

const Result = struct {
    cniVersion: []const u8,

    interfaces: []const Interface,
    ips: []const IpConfig,
    routes: []const Route,

    dns: struct {},

    const Interface = struct {
        name: []const u8,
        mac: []const u8,
        sandbox: ?[]const u8 = null,
    };

    const IpConfig = struct {
        address: []const u8,
        gateway: []const u8,
        interface: usize,
    };

    const Route = struct {
        dst: []const u8,
        gw: []const u8,
    };
};
