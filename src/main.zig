const std = @import("std");

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

fn request_read(reader: std.net.Stream.Reader) !void {
    var read_buf = [_]u8{0} ** 4096;
    const status_line = try std.net.Stream.Reader.readUntilDelimiter(reader, &read_buf, '\n');
    std.log.debug("status line {}", .{status_line});

    for (0..10) |_| {
        const line = try std.net.Stream.Reader.readUntilDelimiter(reader, &read_buf, '\n');
        if (line.len == 1 and line[0] == '\r') {
            break;
        }
    }
}

fn request_reply(writer: std.net.Stream.Writer) !void {
    const res = "HTTP/1.1 200\r\n\r\n";
    try writer.writeAll(res[0..]);
}

fn handle_client(connection: std.net.Server.Connection) !void {
    const reader = connection.stream.reader();
    try request_read(reader);

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
