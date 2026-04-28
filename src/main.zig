const std = @import("std");
const linux = std.os.linux;
const log = std.log;

const tinycni = @import("tinycni");

pub fn main(init: std.process.Init) !void {
    _ = init;

    try namespace();

    var client = try tinycni.Client.init();
    defer client.deinit();

    try client.createVeth("veth0", "veth1");

    try client.upLink(1);

    try client.addIpv4Addr(1, [_]u8{ 10, 0, 0, 1 });

    try client.printLinknames();
    try client.printIpAddresses();
}

fn namespace() !void {
    const unshare_res = linux.unshare(linux.CLONE.NEWNET);
    if (linux.errno(unshare_res) != .SUCCESS) {
        log.err("unshare failed: {}", .{linux.errno(unshare_res)});
        return error.UnshareFailed;
    }
}
