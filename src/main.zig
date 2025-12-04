const std = @import("std");
const Buffer = std.ArrayList;
const Map = std.StringHashMap;

const Error = struct {
	message: []u8,
	pos: u64
};

const TOKEN = enum(u64) {
	BIND,
	IDEN,
	BLOCK,
	OPEN,
	CLOSE,
	INT,
	STR,
	CHAR,
	COMP,
	QUASI,
	FLAT,
	UNQUOTE
};
//NOTE the underlying IR is emitted and retokenized

const Token = struct {
	tag: TOKEN,
	text: []u8,
	pos: u64
};

pub fn main() !void {
	const allocator = std.heap.page_allocator;
	var main_mem = std.heap.ArenaAllocator.init(allocator);
	defer main_mem.deinit();
	const mem = main_mem.allocator();
	const filename = "test.un";
	var infile = std.fs.cwd().openFile(filename, .{}) catch {
		std.debug.print("File not found: {s}\n", .{filename});
		return;
	};
	defer infile.close();
	const stat = infile.stat() catch {
		std.debug.print("Errored file stat: {s}\n", .{filename});
		return;
	};
	const contents = infile.readToEndAlloc(allocator, stat.size+1) catch {
		std.debug.print("Error reading file: {s}\n", .{filename});
		return;
	};
	defer allocator.free(contents);
	var error_log = Buffer(Error).init(mem);
	const tokens = tokenize(&mem, contents, &error_log);
	if (error_log.items.len != 0){
		for (error_log.items) |err| {
			show_error(contents, err);
		}
		return;
	}
	for (tokens.items) |token| {
		show_token(token);
	}
	std.debug.print("\n", .{});
	const program = parse_program(&mem, tokens.items, &error_log) catch {
		for (error_log.items) |err| {
			show_error(contents, err);
		}
		return;
	};
	for (program.items) |expr| {
		show_expr(expr, 1);
	}
	std.debug.print("\n", .{});
}

pub fn show_token(token: Token) void {
	std.debug.print("{s} ", .{token.text});
}

pub fn show_expr(expr: *Expr, depth: u64) void {
	for (0..depth) |_| {
		std.debug.print(" ", .{});
	}
	std.debug.print("( ", .{});
	switch (expr.*){
		.atom => {
			show_token(expr.atom);
		},
		.list => {
			for (expr.list.items) |sub| {
				std.debug.print("\n", .{});
				show_expr(sub, depth+1);
			}
		}
	}
	std.debug.print(")", .{});
}

pub fn show_error(text: []u8, err: Error) void {
	var i: u64 = 0;
	var dist:u64 = 32;
	if (err.pos < dist){
		dist = err.pos;
	}
	var start_pos:u64 = 0;
	var end_pos:u64 = text.len;
	var found_start = false;
	var line:u64 = 1;
	var start_line:u64 = 1;
	while (i < text.len){
		if (text[i] == '\n'){
			line += 1;
		}
		if (i>err.pos-dist and !found_start){
			if (text[i] == '\n'){
				start_pos = i+1;
				found_start = true;
				start_line = line;
			}
		}
		if (i > err.pos+dist){
			if (text[i] == '\n'){
				end_pos = i;
				break;
			}
		}
		i += 1;
	}
	line = start_line;
	const stderr = std.io.getStdErr().writer();
	stderr.print("\x1b[1m{s}\x1b[0m\n", .{err.message})
		catch unreachable;
	stderr.print("{d:06} | ", .{line})
		catch unreachable;
	if (start_pos  >= end_pos){
		start_pos = end_pos;
	}
	for (start_pos .. end_pos) |k| {
		if (text[k] == '\n'){
			line += 1;
			stderr.print("\n{d:06} | ", .{line})
				catch unreachable;
			continue;
		}
		if (k == err.pos){
			stderr.print("\x1b[1;4;31m", .{})
				catch unreachable;
		}
		std.debug.print("{c}", .{text[k]});
		if (k == err.pos){
			stderr.print("\x1b[0m", .{})
				catch unreachable;
		}
	}
	stderr.print("\n", .{})
		catch unreachable;
}

pub fn set_error(mem: *const std.mem.Allocator, index:u64, comptime fmt: []const u8, args: anytype) Error {
	var err = Error{
		.pos = index,
		.message = mem.alloc(u8, 128) catch unreachable,
	};
	const result = std.fmt.bufPrint(err.message, fmt, args)
		catch unreachable;
	err.message.len = result.len;
	return err;
}

pub fn symbol(c: u8) bool {
	if (c == '!' or c == '#' or c == '$' or c == '%' or
		c == '^' or c == '&' or c == '*' or c == '+' or
		c == '-' or c == '/' or c == '?' or c == ':' or
		c == ';' or c == '.' or c == '~' or c == '<' or
		c == '>' or c == '{' or c == '}' or c == '[' or
		c == ']' or c == '='){
		return true;
	}
	return false;
}

pub fn tokenize(mem: *const std.mem.Allocator, text: []u8, err: *Buffer(Error)) Buffer(Token) {
	var i: u64 = 0;
	var tokens = Buffer(Token).init(mem.*);
	var keywords = Map(TOKEN).init(mem.*);
	keywords.put("bind", .BIND) catch unreachable;
	keywords.put("block", .BIND) catch unreachable;
	keywords.put("comptime", .BIND) catch unreachable;
	while (i < text.len) {
		var c = text[i];
		var token = Token {
			.tag=.IDEN,
			.text=undefined,
			.pos = i
		};
		switch (c){
			' ', '\n', '\t' => {
				i += 1;
				continue;
			},
			'(' => {token.tag = .OPEN;},
			')' => {token.tag = .CLOSE;},
			'`' => {token.tag = .QUASI;},
			',' => {token.tag = .UNQUOTE;},
			'@' => {token.tag = .FLAT;},
			else => {}
		}
		if (token.tag != .IDEN){
			token.text = text[i..i+1];
			tokens.append(token)
				catch unreachable;
			i += 1;
			continue;
		}
		if (std.ascii.isAlphanumeric(c) or c == '_'){
			const start = i;
			while (std.ascii.isAlphanumeric(c) or c == '_'){
				i += 1;
				if (i == text.len){
					err.append(set_error(mem, i, "Unexpected end of file in token\n", .{}))
						catch unreachable;
					return tokens;
				}
				c = text[i];
			}
			token.text = text[start .. i];
			if (keywords.get(token.text)) |tag| {
				token.tag = tag;
			}
			tokens.append(token)
				catch unreachable;
			continue;
		}
		else if (symbol(c)){
			const start = i;
			while (symbol(c)){
				i += 1;
				if (i == text.len){
					err.append(set_error(mem, i, "Unexpected end of file in token\n", .{}))
						catch unreachable;
					return tokens;
				}
				c = text[i];
			}
			token.text = text[start .. i];
			tokens.append(token)
				catch unreachable;
			continue;
		}
		else if (c == '"'){
			const start = i;
			i += 1;
			if (i == text.len){
				err.append(set_error(mem, i, "Unexpected end of file in token\n", .{}))
					catch unreachable;
				return tokens;
			}
			c = text[i];
			while (c != '"'){
				i += 1;
				if (i == text.len){
					err.append(set_error(mem, i, "Unexpected end of file in token\n", .{}))
						catch unreachable;
					return tokens;
				}
				c = text[i];
			}
			i += 1;
			token.tag = .STR;
			token.text = text[start .. i];
			tokens.append(token)
				catch unreachable;
			continue;
		}
		else if (c == '\''){
			i += 1;
			if (i == text.len){
				err.append(set_error(mem, i, "Unexpected end of file in token\n", .{}))
					catch unreachable;
				return tokens;
			}
			c = text[i];
			var set_escape = false;
			if (c == '\\'){
				i += 1;
				if (i == text.len){
					err.append(set_error(mem, i, "Unexpected end of file in token\n", .{}))
						catch unreachable;
					return tokens;
				}
				c = text[i];
				token.text = mem.alloc(u8, 1)
					catch unreachable;
				set_escape = true;
				switch (c){
					'e' => {token.text[0] = '\x1b';},
					'r' => {token.text[0] = '\r';},
					't' => {token.text[0] = '\t';},
					'\\' => {token.text[0] = '\\';},
					'\'' => {token.text[0] = '\'';},
					'"' => {token.text[0] = '"';},
					'n' => {token.text[0] = '\n';},
					else => {token.text[0] = c;}
				}
			}
			i += 1;
			if (i == text.len){
				err.append(set_error(mem, i, "Unexpected end of file in token\n", .{}))
					catch unreachable;
				return tokens;
			}
			c = text[i];
			if (c != '\''){
				err.append(set_error(mem, i, "Expected \' to end character token, found {c}\n", .{c}))
					catch unreachable;
				return tokens;
			}
			token.tag = .CHAR;
			if (!set_escape){
				token.text = text[i-2 .. i];
			}
			tokens.append(token)
				catch unreachable;
			i += 1;
			continue;
		}
		err.append(set_error(mem, i, "Unexpected symbol in token stream {c}", .{text[i]}))
			catch unreachable;
		return tokens;
	}
	return tokens;
}

const Expr = union(enum) {
	atom: Token,
	list: Buffer(*Expr)
};

const ParseError = error {
	UnexpectedToken,
	UnexpectedEOF
};

pub fn parse_program(mem: *const std.mem.Allocator, tokens: []Token, err: *Buffer(Error)) ParseError!Buffer(*Expr) {
	var i: u64 = 0;
	var program = Buffer(*Expr).init(mem.*);
	while (i < tokens.len){
		if (tokens[i].tag == .OPEN){
			program.append(try parse_sexpr(mem, tokens, &i, err))
				catch unreachable;
			continue;
		}
		err.append(set_error(mem, i, "Unexpected token for beginning of expression, expected (, found {s}", .{tokens[i].text}))
			catch unreachable;
		return ParseError.UnexpectedToken;
	}
	return program;
}

pub fn parse_sexpr(mem: *const std.mem.Allocator, tokens: []Token, i: *u64, err: *Buffer(Error)) ParseError!*Expr {
	var tok = tokens[i.*];
	std.debug.assert(tok.tag == .OPEN);
	var expr = mem.create(Expr)
		catch unreachable;
	expr.* = Expr{
		.list = Buffer(*Expr).init(mem.*)
	};
	i.* += 1;
	if (i.* == tokens.len){
		err.append(set_error(mem, i.*, "Unexpected end of file in s expression\n", .{}))
			catch unreachable;
		return ParseError.UnexpectedEOF;
	}
	tok = tokens[i.*];
	while (tok.tag != .CLOSE){
		if (tok.tag == .OPEN){
			const subexpr = try parse_sexpr(mem, tokens, i, err);
			expr.list.append(subexpr)
				catch unreachable;
		}
		else {
			const subexpr = Expr{
				.atom = tok
			};
			const loc = mem.create(Expr)
				catch unreachable;
			loc.* = subexpr;
			expr.list.append(loc)
				catch unreachable;
			i.* += 1;
		}
		if (i.* == tokens.len){
			err.append(set_error(mem, i.*, "Unexpected end of file in s expression\n", .{}))
				catch unreachable;
			return ParseError.UnexpectedEOF;
		}
		tok = tokens[i.*];
	}
	i.* += 1;
	return expr;
}
