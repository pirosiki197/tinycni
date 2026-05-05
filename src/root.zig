const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const Client = @import("Client.zig");

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

    pub fn next(self: *Self) ?*const linux.rtattr {
        if (self.offset + @sizeOf(linux.rtattr) > self.buf.len) return null;

        const rta: *const linux.rtattr = @ptrCast(@alignCast(&self.buf[self.offset]));
        if (rta.len < @sizeOf(linux.rtattr) or self.offset + rta.len > self.buf.len) return null;

        self.offset = Alignment.@"4".forward(self.offset + rta.len);
        return rta;
    }
};
pub fn rtaPayload(rta: *const linux.rtattr) []const u8 {
    const start = @sizeOf(linux.rtattr);
    const end = rta.len;
    return @as([*]const u8, @ptrCast(rta))[start..end];
}

pub const Ipv4Addr = struct {
    bytes: [4]u8,

    pub const ParseError = error{
        Overflow,
        InvalidEnd,
        InvalidCharacter,
        Incomplete,
        NonCanonical,
    };

    pub fn parse(buffer: []const u8) ParseError!Ipv4Addr {
        var bytes: [4]u8 = @splat(0);
        var index: u8 = 0;
        var saw_any_digits = false;
        var has_zero_prefix = false;
        for (buffer) |c| switch (c) {
            '.' => {
                if (!saw_any_digits) return error.InvalidCharacter;
                if (index == 3) return error.InvalidEnd;
                index += 1;
                saw_any_digits = false;
                has_zero_prefix = false;
            },
            '0'...'9' => {
                if (c == '0' and !saw_any_digits) {
                    has_zero_prefix = true;
                } else if (has_zero_prefix) {
                    return error.NonCanonical;
                }
                saw_any_digits = true;
                bytes[index] = try std.math.mul(u8, bytes[index], 10);
                bytes[index] = try std.math.add(u8, bytes[index], c - '0');
            },
            else => return error.InvalidCharacter,
        };
        if (index == 3 and saw_any_digits) return .{
            .bytes = bytes,
        };
        return error.Incomplete;
    }

    pub fn string(addr: Ipv4Addr, allocator: Allocator) ![]const u8 {
        const buf = try allocator.alloc(u8, 15);
        var w = std.Io.Writer.fixed(buf);
        try addr.format(&w);
        return w.buffered();
    }

    fn format(addr: Ipv4Addr, w: *std.Io.Writer) !void {
        const bytes = addr.bytes;
        try w.print("{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
    }
};

pub const Ipv4Net = struct {
    addr: Ipv4Addr,
    prefix_len: u8,

    pub const ParseError = error{
        Overflow,
        InvalidEnd,
        InvalidCharacter,
        Incomplete,
        NonCanonical,
    };

    pub fn parse(buffer: []const u8) ParseError!Ipv4Net {
        const subnet_pos = std.mem.findScalar(u8, buffer, '/') orelse return .{
            .addr = try .parse(buffer),
            .prefix_len = 32,
        };
        if (subnet_pos == buffer.len - 1) return error.Incomplete;

        const addr = try Ipv4Addr.parse(buffer[0..subnet_pos]);

        var prefix_len: u8 = 0;
        for (buffer[subnet_pos + 1 ..]) |c| switch (c) {
            '0'...'9' => {
                prefix_len = try std.math.mul(u8, prefix_len, 10);
                prefix_len = try std.math.add(u8, prefix_len, c - '0');
            },
            else => return error.InvalidCharacter,
        };
        return .{
            .addr = addr,
            .prefix_len = prefix_len,
        };
    }

    pub fn string(ipv4net: Ipv4Net, allocator: Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, 18);
        var w = std.Io.Writer.fixed(buf);
        try ipv4net.format(&w);
        return w.buffered();
    }

    fn format(ipv4net: Ipv4Net, w: *std.Io.Writer) !void {
        const bytes = ipv4net.addr.bytes;
        try w.print("{d}.{d}.{d}.{d}/{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3], ipv4net.prefix_len });
    }
};
