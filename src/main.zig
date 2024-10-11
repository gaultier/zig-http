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

fn handle_client(connection: std.net.Server.Connection) !void {
    var read_buf = [_]u8{0} ** 4096;
    const n_read = try connection.stream.read(&read_buf);
    try connection.stream.writeAll(read_buf[0..n_read]);
}

pub fn main() !void {
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
            continue;
        } else { // Child.
            try handle_client(connection);
            return;
        }
    }
}
