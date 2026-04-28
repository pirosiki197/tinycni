const std = @import("std");
const linux = std.os.linux;
const log = std.log;

const tinycni = @import("tinycni");

pub fn main(init: std.process.Init) !void {
    _ = init;

    var host_client = try tinycni.Client.init();
    defer host_client.deinit();

    const netns_fd = linux.open("/var/run/netns/testns", .{}, 0);
    defer _ = linux.close(@intCast(netns_fd));

    try host_client.createVeth("veth0", "veth1");
    const veth1_index = try host_client.getInterfaceIndex("veth1");
    try host_client.setupVeth(netns_fd, veth1_index);

    const veth0_index = try host_client.getInterfaceIndex("veth0");
    try host_client.upLink(veth0_index);
    try host_client.addIpv4Addr(veth0_index, [_]u8{ 10, 0, 0, 1 });

    const n = linux.setns(@intCast(netns_fd), 0);
    if (linux.errno(n) != .SUCCESS) return error.SetnsError;

    var netns_client = try tinycni.Client.init();
    defer netns_client.deinit();

    try netns_client.upLink(1); // lo
    try netns_client.upLink(veth1_index);

    try netns_client.addIpv4Addr(veth1_index, [_]u8{ 10, 0, 0, 2 });

    // try client.printLinknames();
    // try client.printIpAddresses();
}

fn namespace() !void {
    const unshare_res = linux.unshare(linux.CLONE.NEWNET);
    if (linux.errno(unshare_res) != .SUCCESS) {
        log.err("unshare failed: {}", .{linux.errno(unshare_res)});
        return error.UnshareFailed;
    }
}
