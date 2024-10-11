const std = @import("std");

const MAX_HTTP_HEADERS_ALLOWED = 256;

pub const std_options = .{
    // Set the log level to info
    .log_level = .info,

    // Define logFn to override the std implementation
    .logFn = myLogFn,
};

pub fn myLogFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    const prefix = "[" ++ comptime level.asText() ++ "] ";

    // Print the message to stderr, silently ignoring any errors
    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
}

const HttpHeader = struct {
    key: []const u8,
    value: []const u8,
};

const HttpRequest = struct {
    method: enum {
        Get,
        Post,
    },
    path: []const u8,
    headers: []const HttpHeader,
};

fn request_parse_status_line(s: []const u8) !HttpRequest {
    const space = [_]u8{ ' ', '\r' };

    var it = std.mem.splitScalar(u8, s, ' ');

    var req: HttpRequest = undefined;
    if (it.next()) |method| {
        const method_trimmed = std.mem.trim(u8, method, space[0..]);
        std.log.info("method={s} method_trimmed=`{s}`", .{ method, method_trimmed });

        if (std.mem.eql(u8, method_trimmed, "GET")) {
            req.method = .Get;
        } else if (std.mem.eql(u8, method_trimmed, "POST")) {
            req.method = .Post;
        } else {
            return error.InvalidHttpMethod;
        }
    } else {
        return error.InvalidHttpMethod;
    }

    if (it.next()) |path| {
        const path_trimmed = std.mem.trim(u8, path, space[0..]);
        req.path = path_trimmed;
    } else {
        return error.InvalidUri;
    }

    if (it.next()) |http_version| {
        const http_version_trimmed = std.mem.trim(u8, http_version, space[0..]);
        std.log.info("http_version=`{s}`", .{http_version_trimmed});
        if (!std.mem.eql(u8, http_version_trimmed, "HTTP/1.1")) {
            return error.InvalidHttpVersion;
        }
    }

    return req;
}

fn request_read_headers(reader: std.net.Stream.Reader, read_buf: []u8, allocator: std.mem.Allocator) ![]const HttpHeader {
    var headers = std.ArrayList(HttpHeader).init(allocator);
    const space = [_]u8{ ' ', '\r' };

    for (0..MAX_HTTP_HEADERS_ALLOWED) |_| {
        const line = try std.net.Stream.Reader.readUntilDelimiter(reader, &read_buf, '\n');
        if (line.len == 1 and line[0] == '\r') {
            break; // The end.
        }

        var it = std.mem.splitScalar(u8, line, ':');

        var header: HttpHeader = undefined;
        if (it.next()) |key| {
            header.key = std.mem.trim(u8, key, space);
        } else {
            return error.InvalidHttpHeader;
        }
        if (it.next()) |value| {
            header.value = std.mem.trim(u8, value, space);
        } else {
            return error.InvalidHttpHeader;
        }

        if (it.next()) |_| {
            return error.InvalidHttpHeader;
        }

        try headers.append(header);
    }

    return headers.toOwnedSlice();
}

fn request_read(reader: std.net.Stream.Reader, allocator: std.mem.Allocator) !HttpRequest {
    var read_buf = [_]u8{0} ** 4096;
    const status_line = try reader.readUntilDelimiter(&read_buf, '\n');
    const req = try request_parse_status_line(status_line);
    req.headers = try request_read_headers(reader, &read_buf, allocator);

    return req;
}

fn request_reply(writer: std.net.Stream.Writer) !void {
    const res = "HTTP/1.1 200\r\n\r\n";
    try writer.writeAll(res[0..]);
}

fn handle_client(connection: std.net.Server.Connection) !void {
    var buffer: [4096]u8 = undefined; // FIXME: Use mmap?
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    const reader = connection.stream.reader();
    const req = try request_read(reader, allocator);
    std.log.info("req {any}", .{req});

    const writer = connection.stream.writer();
    try request_reply(writer);

    std.posix.exit(0);
}

pub fn main() !void {
    const act: std.posix.Sigaction = .{
        // Set handler to a noop function instead of `SIG.IGN` to prevent
        // leaking signal disposition to a child process.
        .handler = .{ .handler = null },
        .mask = std.posix.empty_sigset,
        .flags = std.posix.SA.NOCLDWAIT,
    };
    try std.posix.sigaction(std.posix.SIG.CHLD, &act, null);
    const addr = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 12345);
    var server = try std.net.Address.listen(addr, .{
        .reuse_port = true,
        .reuse_address = true,
        .kernel_backlog = 1024, // FIXME
    });

    while (true) {
        const connection = try std.net.Server.accept(&server);
        std.log.info("new client {}", .{connection.address});

        const pid = try std.posix.fork();
        if (pid > 0) { // Parent
            connection.stream.close();
            continue;
        } else { // Child.
            try handle_client(connection);
        }
    }
}
