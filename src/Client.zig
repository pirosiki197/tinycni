const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const lib = @import("root.zig");

const Alignment = std.mem.Alignment;

const Self = @This();

fd: usize,
seq: u32 = 0,

const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
};

const nlmsgerr = extern struct {
    err: i32,
    msg: linux.nlmsghdr,
};

pub fn init() !Self {
    const fd = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW, linux.NETLINK.ROUTE);
    if (linux.errno(fd) != .SUCCESS) return error.SocketFailed;
    return .{
        .fd = fd,
    };
}

pub fn deinit(self: Self) void {
    _ = linux.close(@intCast(self.fd));
}

pub fn upLink(self: *Self, index: usize) !void {
    const flags = linux.IFF{
        .UP = true,
    };

    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
    };
    var req = Request{
        .hdr = .{
            .len = @sizeOf(Request),
            .type = .RTM_NEWLINK,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.UNSPEC,
            .type = 0,
            .index = @intCast(index),
            .flags = @as(u16, @bitCast(flags)),
            .change = @as(u16, @bitCast(flags)),
        },
    };

    const sent = linux.sendto(@intCast(self.fd), std.mem.asBytes(&req), @sizeOf(Request), 0, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.SendFailed;

    try self.waitAck();

    self.seq += 1;
}

pub fn addIpv4Addr(self: *Self, index: u32, addr: [4]u8) !void {
    const AddrRequest = extern struct {
        hdr: linux.nlmsghdr,
        msg: ifaddrmsg,
        rta: linux.rtattr,
        addr: [4]u8,
    };
    var addr_req = AddrRequest{
        .hdr = .{
            .len = @sizeOf(AddrRequest),
            .type = .RTM_NEWADDR,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_CREATE | linux.NLM_F_ACK,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.INET,
            .prefixlen = 8,
            .flags = 0,
            .scope = 254,
            .index = index,
        },
        .rta = .{
            .len = @sizeOf(linux.rtattr) + 4,
            .type = .{ .addr = .LOCAL },
        },
        .addr = addr,
    };

    const sent = linux.sendto(@intCast(self.fd), std.mem.asBytes(&addr_req), @sizeOf(AddrRequest), 0, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.SendFailed;

    try self.waitAck();
}

pub fn printLinknames(self: *Self) !void {
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
    };
    var req = Request{
        .hdr = .{
            .len = @sizeOf(Request),
            .type = .RTM_GETLINK,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.UNSPEC,
            .type = 0,
            .index = 0,
            .flags = 0,
            .change = 0,
        },
    };
    const sent = linux.sendto(@intCast(self.fd), std.mem.asBytes(&req), @sizeOf(Request), 0, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.SendFailed;

    var buf: [8192]u8 align(4) = undefined;
    while (true) {
        const n = linux.recvfrom(@intCast(self.fd), &buf, buf.len, 0, null, null);
        if (n == 0) return;
        if (linux.errno(n) != .SUCCESS) return error.RecvFailed;

        var nl_iter = lib.NetlinkIterator(linux.ifinfomsg).init(buf[0..n]);
        while (nl_iter.next()) |msg| {
            if (msg.hdr.type == .DONE) return;

            const ifi = msg.msg.?;
            const flags: linux.IFF = @bitCast(@as(u16, @truncate(ifi.flags)));

            var attrs = msg.attrs;
            while (attrs.next()) |rta| {
                if (rta.type.link == .IFNAME) {
                    const name = lib.rtaPayload(rta);
                    log.info("Interface {s}: {s}", .{
                        name[0 .. name.len - 1],
                        if (flags.UP) "UP" else "DOWN",
                    });
                }
            }
        }
    }

    self.seq += 1;
}

pub fn printIpAddresses(self: *Self) !void {
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: ifaddrmsg,
    };
    var req = Request{
        .hdr = .{
            .len = @sizeOf(Request),
            .type = .RTM_GETADDR,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.INET,
            .prefixlen = 0,
            .flags = 0,
            .scope = 0,
            .index = 0,
        },
    };
    const sent = linux.sendto(@intCast(self.fd), std.mem.asBytes(&req), @sizeOf(Request), 0, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.SendFailed;

    var buf: [8192]u8 align(4) = undefined;
    while (true) {
        const n = linux.recvfrom(@intCast(self.fd), &buf, buf.len, 0, null, null);
        if (linux.errno(n) != .SUCCESS) return error.RecvFailed;

        var nl_iter = lib.NetlinkIterator(ifaddrmsg).init(buf[0..n]);

        while (nl_iter.next()) |msg| {
            if (msg.hdr.type == .DONE) return;

            const ifa = msg.msg.?;
            if (ifa.family != linux.AF.INET) continue;

            var attrs = msg.attrs;
            while (attrs.next()) |rta| {
                if (rta.type.addr != .LOCAL) continue;

                const data = lib.rtaPayload(rta);
                log.info("Interface {}: IP {}.{}.{}.{}", .{
                    ifa.index,
                    data[0],
                    data[1],
                    data[2],
                    data[3],
                });
            }
        }
    }

    self.seq += 1;
}

pub fn createVeth(self: *Self, name: []const u8, peer_name: []const u8) !void {
    const IFLA_INFO_KIND = 1;
    const IFLA_INFO_DATA = 2;
    const VETH_INFO_PEER = 1;

    // RTM_NEWLINK
    // └─ IFLA_IFNAME = "veth0"
    // └─ IFLA_LINKINFO
    //     └─ kind = "veth"
    //     └─ data
    //         └─ VETH_INFO_PEER
    //             └─ (peer ifinfomsg + attrs)

    var buf_array: [512]u8 align(4) = undefined;
    const buf = buf_array[0..];
    var offset: usize = 0;

    // -- ifname --
    const ifname = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.IFNAME));
    writeCString(buf, &offset, name);
    ifname.end(&offset);

    // -- link info --
    const linkinfo = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.LINKINFO));

    const kind = Attr.start(buf, &offset, IFLA_INFO_KIND);
    writeCString(buf, &offset, "veth");
    kind.end(&offset);

    const data = Attr.start(buf, &offset, IFLA_INFO_DATA);

    const peer = Attr.start(buf, &offset, VETH_INFO_PEER);

    const peer_ifi: *linux.ifinfomsg = @ptrCast(@alignCast(&buf[offset]));
    peer_ifi.* = .{
        .family = linux.AF.UNSPEC,
        .type = 0,
        .index = 0,
        .flags = 0,
        .change = 0,
    };
    offset += @sizeOf(linux.ifinfomsg);

    const peer_ifname = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.IFNAME));
    writeCString(buf, &offset, peer_name);
    peer_ifname.end(&offset);

    peer.end(&offset);
    data.end(&offset);
    linkinfo.end(&offset);

    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) + offset;
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
        buf: [512]u8,
    };
    const req = Request{
        .hdr = .{
            .type = .RTM_NEWLINK,
            .len = @truncate(total_len),
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_CREATE | linux.NLM_F_EXCL | linux.NLM_F_ACK,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.UNSPEC,
            .type = 0,
            .index = 0,
            .flags = 0,
            .change = 0,
        },
        .buf = buf_array,
    };

    const sent = linux.sendto(@intCast(self.fd), std.mem.asBytes(&req), total_len, 0, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.SendFailed;

    try self.waitAck();

    self.seq += 1;
}

fn waitAck(self: Self) !void {
    var buf: [4096]u8 align(4) = undefined;
    while (true) {
        const n = linux.recvfrom(@intCast(self.fd), &buf, buf.len, 0, null, null);
        const err = linux.errno(n);
        if (err != .SUCCESS) return error.RecvFailed;

        var it = lib.NetlinkIterator(linux.ifinfomsg).init(buf[0..n]);
        while (it.next()) |msg| {
            if (msg.hdr.seq != self.seq) continue;

            if (msg.hdr.type == .DONE) return;
            if (msg.hdr.type == .ERROR) {
                const nlerr: *const nlmsgerr = @ptrCast(@alignCast(msg.msg.?));
                if (nlerr.err == 0) return;
                log.err("Kernel Error: {} (seq: {})", .{ -nlerr.err, self.seq });
                return error.NetlinkKernelError;
            }
        }
    }
    self.seq += 1;
}

const Attr = struct {
    s: usize,
    rta: *linux.rtattr,

    fn start(buf: []u8, offset: *usize, rta_type: u16) Attr {
        const s = offset.*;
        const rta: *linux.rtattr = @ptrCast(@alignCast(&buf[offset.*]));
        rta.type = .{ .link = @enumFromInt(rta_type) };
        rta.len = @sizeOf(linux.rtattr);
        offset.* += @sizeOf(linux.rtattr);

        return .{
            .s = s,
            .rta = rta,
        };
    }

    fn end(self: Attr, offset: *usize) void {
        self.rta.len = @truncate(offset.* - self.s);
        offset.* = Alignment.@"4".forward(offset.*);
    }
};

fn writeCString(buf: []u8, offset: *usize, s: []const u8) void {
    @memcpy(buf[offset.*..].ptr, s);
    offset.* += s.len;
    buf[offset.*] = 0;
    offset.* += 1;
}
