const std = @import("std");
const linux = std.os.linux;
const Alignment = std.mem.Alignment;

pub const Client = @import("Client.zig");

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

const IFLA_INFO = enum(c_ushort) {
    UNSPEC,
    KIND,
    DATA,
    _,
};

const VETH_INFO = enum(c_ushort) {
    UNSPEC,
    PEER,
    _,
};

pub const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: RT_SCOPE,
    index: u32,
};

pub const rtmsg = extern struct {
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

pub const nlmsgerr = extern struct {
    err: i32,
    msg: linux.nlmsghdr,
};

pub const rtattr = extern struct {
    len: u16,
    type: Type,

    pub const Type = extern union {
        link: linux.IFLA,
        addr: linux.IFA,
        link_info: IFLA_INFO,
        veth_info: VETH_INFO,
    };

    pub fn payload(rta: *const rtattr) []const u8 {
        const start = @sizeOf(rtattr);
        const end = rta.len;
        return @as([*]const u8, @ptrCast(rta))[start..end];
    }
};

pub fn NetlinkIterator(PayloadType: type) type {
    return struct {
        buf: []const u8,
        offset: usize = 0,

        const Self = @This();

        pub const DecodedMessage = struct {
            hdr: *const linux.nlmsghdr,
            msg: ?*const PayloadType,
            attrs: RtAttrIterator,
        };

        pub fn init(buf: []const u8) Self {
            return .{
                .buf = buf,
            };
        }

        pub fn next(self: *Self) ?DecodedMessage {
            if (self.offset + @sizeOf(linux.nlmsghdr) > self.buf.len) return null;

            const hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&self.buf[self.offset]));
            if (self.offset + hdr.len > self.buf.len) return null;

            const payload_size = @sizeOf(PayloadType);
            const has_payload = @sizeOf(linux.nlmsghdr) + payload_size <= hdr.len;

            var msg_ptr: ?*const PayloadType = null;
            var attr_start = self.offset + @sizeOf(linux.nlmsghdr);
            if (has_payload) {
                msg_ptr = @ptrCast(@alignCast(&self.buf[attr_start]));
                attr_start += payload_size;
            }

            const attr_end = self.offset + hdr.len;
            const attr_data = if (attr_start < attr_end) self.buf[attr_start..attr_end] else self.buf[0..0];

            self.offset = Alignment.@"4".forward(self.offset + hdr.len);

            return .{
                .hdr = hdr,
                .msg = msg_ptr,
                .attrs = RtAttrIterator.init(attr_data),
            };
        }
    };
}

pub const RtAttrIterator = struct {
    buf: []const u8,
    offset: usize = 0,

    const Self = @This();

    pub fn init(buf: []const u8) Self {
        return .{
            .buf = buf,
        };
    }

    pub fn next(self: *Self) ?*const rtattr {
        if (self.offset + @sizeOf(rtattr) > self.buf.len) return null;

        const rta: *const rtattr = @ptrCast(@alignCast(&self.buf[self.offset]));
        if (rta.len < @sizeOf(rtattr) or self.offset + rta.len > self.buf.len) return null;

        self.offset = Alignment.@"4".forward(self.offset + rta.len);
        return rta;
    }
};
