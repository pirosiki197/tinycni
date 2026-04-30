const std = @import("std");
const linux = std.os.linux;
const log = std.log;

const tinycni = @import("tinycni");

const bridge_name = "tinycnibridge0";

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var host_client = try tinycni.Client.init();
    defer host_client.deinit();

    const netns_fd = linux.open("/var/run/netns/testns", .{}, 0);
    defer _ = linux.close(@intCast(netns_fd));

    const bridge_index = host_client.ifnameToIndex(bridge_name) catch blk: {
        try host_client.createBridge(bridge_name);
        const bridge_index = try host_client.ifnameToIndex(bridge_name);
        try host_client.upLink(bridge_index);
        try host_client.addIpv4Addr(bridge_index, [_]u8{ 10, 0, 0, 1 });
        try configureNat(io, "eth0");
        break :blk bridge_index;
    };

    try host_client.createVeth("veth0", "veth1");
    const veth1_index = try host_client.ifnameToIndex("veth1");
    try host_client.moveLinkToNetns(netns_fd, veth1_index);

    const veth0_index = try host_client.ifnameToIndex("veth0");
    try host_client.upLink(veth0_index);
    try host_client.attachToBridge(veth0_index, bridge_index);

    const n = linux.setns(@intCast(netns_fd), 0);
    if (linux.errno(n) != .SUCCESS) return error.SetnsError;

    var netns_client = try tinycni.Client.init();
    defer netns_client.deinit();

    const netns_veth1_index = try netns_client.ifnameToIndex("veth1");

    try netns_client.upLink(1); // lo
    try netns_client.upLink(netns_veth1_index);

    try netns_client.addIpv4Addr(netns_veth1_index, [_]u8{ 10, 0, 0, 2 });

    try netns_client.setDefaultGateway(netns_veth1_index, [_]u8{ 10, 0, 0, 1 });
}

const container_cidr = "10.0.0.0/24";

fn configureNat(io: std.Io, out: []const u8) !void {
    var proc = try std.process.spawn(io, .{
        .argv = &.{
            "iptables",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            container_cidr,
            "-o",
            out,
            "-j",
            "MASQUERADE",
        },
    });
    _ = try proc.wait(io);
}
