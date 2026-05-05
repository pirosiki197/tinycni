const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const lib = @import("root.zig");

const Alignment = std.mem.Alignment;

const Self = @This();

fd: usize,
seq: u32 = 0,

pub const Link = struct {
    index: u32,
    mac: [6]u8,
    flags: u32,
    mtu: u32,
};

const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: RT_SCOPE,
    index: u32,
};

const rtmsg = extern struct {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: RT_TABLE,
    protocol: RTPROT,
    scope: RT_SCOPE,
    type: RTN,
    flags: u32,
};

const nlmsgerr = extern struct {
    err: i32,
    msg: linux.nlmsghdr,
};

const RTPROT = enum(u8) {
    UNSPEC = 0,
    REDIRECT = 1,
    KERNEL = 2,
    BOOT = 3,
    STATIC = 4,
    _,
};

const RT_SCOPE = enum(u8) {
    UNIVERSE = 0,
    SITE = 200,
    LINK = 253,
    HOST = 254,
    NOWHERE = 255,
};

const RT_TABLE = enum(u8) {
    UNSPEC = 0,

    COMPAT = 252,
    DEFAULT = 253,
    MAIN = 254,
    LOCAL = 255,

    _,
};

const RTN = enum(u8) {
    UNSPEC,
    UNICAST,
    LOCAL,
    BROADCAST,
    ANYCAST,
    MULTICAST,
    BLACKHOLE,
    UNREACHABLE,
    PROHIBIT,
    THROW,
    NAT,
    XRESOLVE,
};

const IFLA_INFO_KIND = 1;
const IFLA_INFO_DATA = 2;
const VETH_INFO_PEER = 1;

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

pub fn upLink(self: *Self, index: u32) !void {
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
}

pub fn getLinkByName(self: *Self, name: []const u8) !Link {
    var buf_array: [64]u8 = undefined;
    const buf = &buf_array;
    var offset: usize = 0;

    const ifname = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.IFNAME));
    writeCString(buf, &offset, name);
    ifname.end(&offset);

    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) + offset;
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
        buf: [64]u8,
    };
    var req = Request{
        .hdr = .{
            .len = @truncate(total_len),
            .type = .RTM_GETLINK,
            .flags = linux.NLM_F_REQUEST,
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
    try self.send(std.mem.asBytes(&req)[0..total_len]);

    defer self.seq += 1;

    var res_buf: [8192]u8 align(4) = undefined;
    var link: Link = undefined;

    const n = linux.recvfrom(@intCast(self.fd), &res_buf, res_buf.len, 0, null, null);
    if (linux.errno(n) != .SUCCESS) return error.RecvFailed;

    var nl_iter = lib.NetlinkIterator(linux.ifinfomsg).init(res_buf[0..n]);
    while (nl_iter.next()) |msg| {
        if (msg.hdr.seq != self.seq) continue;
        if (msg.hdr.type == .ERROR) return error.NetlinkError;

        const ifi = msg.msg.?;
        link.index = @intCast(ifi.index);
        link.flags = ifi.flags;

        var attrs = msg.attrs;
        while (attrs.next()) |rta| {
            switch (rta.type.link) {
                .ADDRESS => @memcpy(link.mac[0..6], lib.rtaPayload(rta)),
                .MTU => link.mtu = std.mem.readInt(u32, @ptrCast(lib.rtaPayload(rta)), .native),
                else => {},
            }
        }
    }

    return link;
}

pub fn moveLinkToNetns(self: *Self, netns_fd: usize, veth_index: u32) !void {
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
        rta: linux.rtattr,
        fd: i32,
    };
    const req = Request{
        .hdr = .{
            .type = .RTM_SETLINK,
            .len = @sizeOf(Request),
            .seq = self.seq,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.UNSPEC,
            .index = @intCast(veth_index),
            .flags = 0,
            .type = 0,
            .change = 0,
        },
        .rta = .{
            .type = .{ .link = .NET_NS_FD },
            .len = @sizeOf(linux.rtattr) + @sizeOf(i32),
        },
        .fd = @intCast(netns_fd),
    };
    const sent = linux.sendto(@intCast(self.fd), std.mem.asBytes(&req), @sizeOf(Request), 0, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.SendFiled;

    try self.waitAck();
}

pub fn attachToBridge(self: *Self, ifindex: u32, bridge_index: u32) !void {
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
        rta: linux.rtattr,
        bridge_index: u32,
    };
    const req = Request{
        .hdr = .{
            .type = .RTM_NEWLINK,
            .len = @sizeOf(Request),
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.UNSPEC,
            .index = @intCast(ifindex),
            .type = 0,
            .flags = 0,
            .change = 0,
        },
        .rta = .{
            .type = .{ .link = .MASTER },
            .len = @sizeOf(linux.rtattr) + @sizeOf(u32),
        },
        .bridge_index = bridge_index,
    };
    try self.send(std.mem.asBytes(&req)[0..@sizeOf(Request)]);

    try self.waitAck();
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
            .prefixlen = 24,
            .flags = 0,
            .scope = .UNIVERSE,
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

pub fn renameInterface(self: *Self, index: u32, new_name: []const u8) !void {
    var buf_array: [64]u8 = undefined;
    const buf = buf_array[0..];
    var offset: usize = 0;

    const rta = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.IFNAME));
    writeCString(buf, &offset, new_name);
    rta.end(&offset);

    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) + offset;
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
        buf: [64]u8,
    };
    const req = Request{
        .hdr = .{
            .type = .RTM_SETLINK,
            .len = @truncate(total_len),
            .seq = self.seq,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.UNSPEC,
            .index = @intCast(index),
            .type = 0,
            .flags = 0,
            .change = 0,
        },
        .buf = buf_array,
    };
    try self.send(std.mem.asBytes(&req)[0..total_len]);

    try self.waitAck();
}

pub fn createVeth(self: *Self, name: []const u8, mac: [6]u8, peer_name: []const u8, peer_mac: [6]u8) !void {
    // RTM_NEWLINK
    // └─ IFLA_IFNAME = "veth0"
    // └─ IFLA_ADDRESS = mac
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

    const address = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.ADDRESS));
    writeData(buf, &offset, &mac);
    address.end(&offset);

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

    const peer_address = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.ADDRESS));
    writeData(buf, &offset, &peer_mac);
    peer_address.end(&offset);

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
}

pub fn createBridge(self: *Self, bridge_name: []const u8) !void {
    var buf_array: [128]u8 = undefined;
    const buf = buf_array[0..];
    var offset: usize = 0;

    const ifname = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.IFNAME));
    writeCString(buf, &offset, bridge_name);
    ifname.end(&offset);

    const linkinfo = Attr.start(buf, &offset, @intFromEnum(linux.IFLA.LINKINFO));
    const kind = Attr.start(buf, &offset, IFLA_INFO_KIND);
    writeCString(buf, &offset, "bridge");
    kind.end(&offset);
    linkinfo.end(&offset);

    const total_len = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) + offset;
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
        buf: [128]u8,
    };
    const req = Request{
        .hdr = .{
            .type = .RTM_NEWLINK,
            .len = @truncate(total_len),
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_CREATE | linux.NLM_F_ACK,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.UNSPEC,
            .type = 0,
            .flags = 0,
            .index = 0,
            .change = 0,
        },
        .buf = buf_array,
    };
    try self.send(std.mem.asBytes(&req)[0..total_len]);

    try self.waitAck();
}

pub fn setDefaultGateway(self: *Self, ifindex: u32, gw: [4]u8) !void {
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: rtmsg,
        gw_rta: linux.rtattr,
        gw: [4]u8,
        oif_rta: linux.rtattr,
        ifindex: u32,
    };
    var req = Request{
        .hdr = .{
            .len = @sizeOf(Request),
            .type = .RTM_NEWROUTE,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_CREATE | linux.NLM_F_EXCL | linux.NLM_F_ACK,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.INET,
            .dst_len = 0,
            .src_len = 0,
            .tos = 0,
            .table = .MAIN,
            .protocol = .STATIC,
            .scope = .UNIVERSE,
            .type = .UNICAST,
            .flags = 0,
        },
        .gw_rta = .{
            .len = @sizeOf(linux.rtattr) + 4,
            .type = .{ .link = @enumFromInt(5) }, // RTA_GATEWAY
        },
        .gw = gw,
        .oif_rta = .{
            .len = @sizeOf(linux.rtattr) + @sizeOf(u32),
            .type = .{ .link = @enumFromInt(4) }, // RTA_OIF
        },
        .ifindex = ifindex,
    };

    const sent = linux.sendto(@intCast(self.fd), std.mem.asBytes(&req), @sizeOf(Request), 0, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.SendFailed;

    try self.waitAck();
}

pub fn deleteInterface(self: *Self, index: u32) !void {
    const Request = extern struct {
        hdr: linux.nlmsghdr,
        msg: linux.ifinfomsg,
    };
    const req = Request{
        .hdr = .{
            .type = .RTM_DELLINK,
            .len = @sizeOf(Request),
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK,
            .seq = self.seq,
            .pid = 0,
        },
        .msg = .{
            .family = linux.AF.UNSPEC,
            .index = @intCast(index),
            .flags = 0,
            .type = 0,
            .change = 0,
        },
    };

    try self.send(std.mem.asBytes(&req)[0..@sizeOf(Request)]);

    try self.waitAck();
}

fn send(self: Self, req: []const u8) !void {
    const sent = linux.sendto(@intCast(self.fd), req.ptr, req.len, 0, null, 0);
    const err = linux.errno(sent);
    if (err != .SUCCESS) {
        log.err("Kernel Error: {}", .{err});
        return error.SendFailed;
    }
}

fn waitAck(self: *Self) !void {
    defer self.seq += 1;

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

fn writeData(buf: []u8, offset: *usize, data: []const u8) void {
    @memcpy(buf[offset.*..].ptr, data);
    offset.* += data.len;
}
