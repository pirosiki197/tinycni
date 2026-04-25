const std = @import("std");
const linux = std.os.linux;
const log = std.log;
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
