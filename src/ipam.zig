const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const File = std.Io.File;
const net = @import("net.zig");
const Ipv4Addr = net.Ipv4Addr;
const Ipv4Net = net.Ipv4Net;

pub const Manager = struct {
    allocator: Allocator,
    config_path: []const u8,
    gateway: Ipv4Addr,
    cidr: Ipv4Net,

    const Self = @This();

    pub fn init(allocator: Allocator, config_path: []const u8, gw: Ipv4Addr, cidr: Ipv4Net) Self {
        return .{
            .allocator = allocator,
            .config_path = config_path,
            .gateway = gw,
            .cidr = cidr,
        };
    }

    pub fn alloc(self: Self, io: std.Io, container_id: []const u8) !Ipv4Addr {
        const dir = try Dir.openDirAbsolute(io, self.config_path, .{ .iterate = true });
        defer dir.close(io);

        while (true) {
            const allocated_ip = try self.find_available_ip(io, dir);
            const ip_str = try allocated_ip.string(self.allocator);
            defer self.allocator.free(ip_str);

            const file = dir.createFile(io, ip_str, .{ .exclusive = true }) catch |err| {
                if (err == File.OpenError.PathAlreadyExists) continue;
                return err;
            };
            defer file.close(io);

            var buf: [64]u8 = undefined;
            var writer = file.writer(io, &buf);
            try writer.interface.writeAll(container_id);
            try writer.flush();

            return allocated_ip;
        }
    }

    pub fn free(self: Self, io: std.Io, container_id: []const u8) !void {
        const dir = try Dir.openDirAbsolute(io, self.config_path, .{ .iterate = true });
        defer dir.close(io);

        var iter = dir.iterate();
        while (try iter.next(io)) |f| {
            if (f.kind != .file) continue;
            const file = try dir.openFile(io, f.name, .{});
            defer file.close(io);

            var buf: [64]u8 = undefined;
            var reader = file.reader(io, &buf);

            const content = try reader.interface.allocRemaining(self.allocator, .unlimited);
            defer self.allocator.free(content);
            if (std.mem.eql(u8, content, container_id)) {
                try dir.deleteFile(io, f.name);
                return;
            }
        }
    }

    fn find_available_ip(self: Self, io: std.Io, dir: Dir) !Ipv4Addr {
        var ips: std.hash_map.AutoHashMap(u32, void) = .init(self.allocator);
        defer ips.deinit();
        var iter = dir.iterate();
        while (try iter.next(io)) |f| {
            if (f.kind != .file) continue;
            const ip = try Ipv4Addr.parse(f.name);
            try ips.put(ip.asu32(), {});
        }

        var ip = self.cidr.addr.asu32() + 1; // skip network address
        const host_bits = @as(u5, @truncate(32 - self.cidr.prefix_len));
        const num_hosts = (@as(u32, 1) << host_bits) - 1;
        const broadcast_ip = self.cidr.addr.asu32() + num_hosts;
        while (ip < broadcast_ip) : (ip += 1) {
            if (ips.contains(ip)) continue;
            if (ip == self.gateway.asu32()) continue;
            break;
        }

        return .fromu32(ip);
    }
};
