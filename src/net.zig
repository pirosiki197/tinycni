const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Link = struct {
    index: u32,
    mac: Mac,
    flags: u32,
    mtu: u32,
};

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

    pub fn asu32(addr: Ipv4Addr) u32 {
        return @as(u32, addr.bytes[0]) << 24 | @as(u32, addr.bytes[1]) << 16 | @as(u32, addr.bytes[2]) << 8 | @as(u32, addr.bytes[3]);
    }

    pub fn fromu32(addr: u32) Ipv4Addr {
        return .{
            .bytes = [_]u8{
                @truncate(addr >> 24),
                @truncate(addr >> 16),
                @truncate(addr >> 8),
                @truncate(addr),
            },
        };
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

        const network_addr = addr.asu32() & ~(@as(u32, 1) << @as(u5, @truncate(32 - prefix_len)) - 1);

        return .{
            .addr = .fromu32(network_addr),
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

pub const Mac = struct {
    bytes: [6]u8,

    pub fn fromBytes(bytes: [6]u8) Mac {
        return .{ .bytes = bytes };
    }

    pub fn string(mac: Mac, allocator: Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, 17);
        var w = std.Io.Writer.fixed(buf);
        try mac.format(&w);
        return w.buffered();
    }

    fn format(mac: Mac, w: *std.Io.Writer) !void {
        const bytes = mac.bytes;
        try w.print("{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
        });
    }
};
