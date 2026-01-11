const std = @import("std");
const ir = @import("vm");
const Buffer = std.ArrayList;
const Map = std.StringHashMap;

var internal_uid: []const u8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

var debug = true;

const Error = struct {
	message: []u8,
	pos: u64
};

const TOKEN = enum(u64) {
	BIND,
	USE,
	IDEN,
	OPEN,
	CLOSE,
	NUM,
	STR,
	CHAR,
	COMP,
	FLAT,
	UID,
	REG,
	LABEL,
	REIF,
	MOV,
	ADD, SUB, MUL, DIV, MOD,
	UADD, USUB, UMUL, UDIV, UMOD,
	SHR, SHL,
	AND, OR, XOR,
	NOT, COM,
	CMP,
	JMP, JEQ, JNE, JGT, JGE, JLT, JLE,
	CALL, RET,
	PSH, POP,
	INT,
	AT,
	REG0,
	REG1,
	REG2,
	REG3,
	REG4,
	REG5,
	REG6,
	REG7,
	REG8,
	REG9,
	REG10,
	REG11,
	FPTR,
	SPTR
};

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
	const args = try std.process.argsAlloc(mem);
	if (args.len == 1){
		std.debug.print("Pass -h for help\n", .{});
		return;
	}
	if (std.mem.eql(u8, args[1], "-h")){
		std.debug.print("Help Menu\n", .{});
		std.debug.print("   -h                 : Show this menu\n", .{});
		std.debug.print("   [infile]           : Run [infile]\n", .{});
		std.debug.print("   [infile] [outfile] : Compile [infile] to [outfile]\n", .{});
		return;
	}
	const filename = args[1];
	var eval = true;
	var outfilename = filename;
	if (args.len == 3){
		eval = false;
		outfilename = args[2];
	}
	const contents = try get_contents(&mem, filename);
	var error_log = Buffer(Error).init(mem);
	const tokens = tokenize(&mem, contents, &error_log);
	if (error_log.items.len != 0){
		for (error_log.items) |err| {
			show_error(contents, err);
		}
		return;
	}
	if (debug){
		for (tokens.items) |token| {
			show_token(token);
		}
		std.debug.print("\n", .{});
	}
	const raw_expressions = parse_program(&mem, tokens.items, &error_log) catch {
		for (error_log.items) |err| {
			show_error(contents, err);
		}
		return;
	};
	if (debug){
		for (raw_expressions.items) |expr| {
			show_expr(expr, 1);
		}
		std.debug.print("\n", .{});
	}
	var program = Program.init(&mem);
	const default_target = Token {
		.text = mem.dupe(u8, "vm") catch unreachable,
		.pos = 0,
		.tag=.IDEN
	};
	const val = program.compute(raw_expressions, default_target, &error_log, eval) catch {
		for (error_log.items) |err| {
			show_error(contents, err);
		}
		return;
	};
	if (!eval){
		var normalized = Buffer(*Expr).init(program.mem.*);
		if (program.normalize(&normalized, val, true) == null){
			std.debug.print("Failed normalization parse\n", .{});
			return;
		}
		program.prepend_reif(&normalized);
		normalized = program.color_cfg(&normalized);
		program.flatten_interrupts(&normalized);
		program.inscribe_labels(&normalized);
		var final = Expr{
			.list = normalized
		};
		write_out(outfilename, &final);
	}
}

pub fn write_out(outfile: []u8, val: *Expr) void {
	var out = std.fs.cwd().createFile(outfile, .{.truncate=true}) catch {
		std.debug.print("Error creating file: {s}\n", .{outfile});
		return;
	};
	defer out.close();
	write_expr(out, val, 1);
}


pub fn write_expr(out:std.fs.File, expr: *Expr, depth: u64) void {
	for (0..depth) |_| {
		out.writer().print(" ", .{})
			catch unreachable;
	}
	out.writer().print("( ", .{})
		catch unreachable;
	switch (expr.*){
		.atom => {
			switch (expr.atom.tag){
				.REG0 => { out.writer().print("r0 ", .{}) catch unreachable; },
				.REG1 => { out.writer().print("r1 ", .{}) catch unreachable; },
				.REG2 => { out.writer().print("r2 ", .{}) catch unreachable; },
				.REG3 => { out.writer().print("r3 ", .{}) catch unreachable; },
				.REG4 => { out.writer().print("r4 ", .{}) catch unreachable; },
				.REG5 => { out.writer().print("r5 ", .{}) catch unreachable; },
				.REG6 => { out.writer().print("r6 ", .{}) catch unreachable; },
				.REG7 => { out.writer().print("r7 ", .{}) catch unreachable; },
				.REG8 => { out.writer().print("r8 ", .{}) catch unreachable; },
				.REG9 => { out.writer().print("r9 ", .{}) catch unreachable; },
				.REG10 => { out.writer().print("r10 ", .{}) catch unreachable; },
				.REG11 => { out.writer().print("r11 ", .{}) catch unreachable; },
				.SPTR => { out.writer().print("sp ", .{}) catch unreachable; },
				.FPTR => { out.writer().print("fp ", .{}) catch unreachable; },
				else => {
					out.writer().print("{s} ", .{expr.atom.text})
						catch unreachable;
				}
			}
		},
		.list => {
			for (expr.list.items) |sub| {
				if (sub.* == .list){
					out.writer().print("\n", .{})
						catch unreachable;
					write_expr(out, sub, depth+1);
				}
				else{
					switch (sub.atom.tag){
						.REG0 => { out.writer().print("r0 ", .{}) catch unreachable; },
						.REG1 => { out.writer().print("r1 ", .{}) catch unreachable; },
						.REG2 => { out.writer().print("r2 ", .{}) catch unreachable; },
						.REG3 => { out.writer().print("r3 ", .{}) catch unreachable; },
						.REG4 => { out.writer().print("r4 ", .{}) catch unreachable; },
						.REG5 => { out.writer().print("r5 ", .{}) catch unreachable; },
						.REG6 => { out.writer().print("r6 ", .{}) catch unreachable; },
						.REG7 => { out.writer().print("r7 ", .{}) catch unreachable; },
						.REG8 => { out.writer().print("r8 ", .{}) catch unreachable; },
						.REG9 => { out.writer().print("r9 ", .{}) catch unreachable; },
						.REG10 => { out.writer().print("r10 ", .{}) catch unreachable; },
						.REG11 => { out.writer().print("r11 ", .{}) catch unreachable; },
						.SPTR => { out.writer().print("sp ", .{}) catch unreachable; },
						.FPTR => { out.writer().print("fp ", .{}) catch unreachable; },
						else => {
							out.writer().print("{s} ", .{sub.atom.text})
								catch unreachable;
						}
					}				
				}
			}
		}
	}
	out.writer().print(") ", .{})
		catch unreachable;
}

pub fn get_contents(mem: *const std.mem.Allocator, filename: []u8) ![]u8 {
	var infile = std.fs.cwd().openFile(filename, .{}) catch |err| {
		std.debug.print("File not found: {s}\n", .{filename});
		return err;
	};
	defer infile.close();
	const stat = infile.stat() catch |err| {
		std.debug.print("Errored file stat: {s}\n", .{filename});
		return err;
	};
	const contents = infile.readToEndAlloc(mem.*, stat.size+1) catch |err| {
		std.debug.print("Error reading file: {s}\n", .{filename});
		return err;
	};
	return contents;
}

pub fn show_token(token: Token) void {
	std.debug.print("{s} ", .{token.text});
	if (token.tag == .NUM){
		std.debug.print("[numeric] ", .{});
	}
	if (token.tag == .STR){
		std.debug.print("[str] ", .{});
	}
	if (token.tag == .REG0){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG1){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG2){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG3){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG4){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG5){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG6){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG7){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG8){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG9){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG10){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .REG11){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .FPTR){
		std.debug.print("[{}] ", .{token.tag});
	}
	if (token.tag == .SPTR){
		std.debug.print("[{}] ", .{token.tag});
	}
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
				if (sub.* == .list){
					std.debug.print("\n", .{});
					show_expr(sub, depth+1);
				}
				else{
					show_token(sub.atom);
				}
			}
		}
	}
	std.debug.print(") ", .{});
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
		c == '^' or c == '`' or c == '*' or c == '+' or
		c == '-' or c == '/' or c == '?' or c == ':' or
		c == ';' or c == '.' or c == '~' or c == '<' or
		c == '>' or c == '{' or c == '}' or c == '[' or
		c == ']' or c == '=' or c == ','){
		return true;
	}
	return false;
}

pub fn tokenize(mem: *const std.mem.Allocator, text: []u8, err: *Buffer(Error)) Buffer(Token) {
	var i: u64 = 0;
	var tokens = Buffer(Token).init(mem.*);
	var keywords = Map(TOKEN).init(mem.*);
	keywords.put("bind", .BIND) catch unreachable;
	keywords.put("use", .USE) catch unreachable;
	keywords.put("flat", .FLAT) catch unreachable;
	keywords.put("uid", .UID) catch unreachable;
	keywords.put("comp", .COMP) catch unreachable;
	keywords.put("reg", .REG) catch unreachable;
	keywords.put("label", .LABEL) catch unreachable;
	keywords.put("reif", .REIF) catch unreachable;
	keywords.put("mov", .MOV) catch unreachable;
	keywords.put("add", .ADD) catch unreachable;
	keywords.put("sub", .SUB) catch unreachable;
	keywords.put("mul", .MUL) catch unreachable;
	keywords.put("div", .DIV) catch unreachable;
	keywords.put("mod", .MOD) catch unreachable;
	keywords.put("uadd", .UADD) catch unreachable;
	keywords.put("usub", .USUB) catch unreachable;
	keywords.put("umul", .UMUL) catch unreachable;
	keywords.put("udiv", .UDIV) catch unreachable;
	keywords.put("umod", .UMOD) catch unreachable;
	keywords.put("shl", .SHL) catch unreachable;
	keywords.put("shr", .SHR) catch unreachable;
	keywords.put("and", .AND) catch unreachable;
	keywords.put("or", .OR) catch unreachable;
	keywords.put("xor", .XOR) catch unreachable;
	keywords.put("not", .NOT) catch unreachable;
	keywords.put("com", .COM) catch unreachable;
	keywords.put("cmp", .CMP) catch unreachable;
	keywords.put("psh", .PSH) catch unreachable;
	keywords.put("pop", .POP) catch unreachable;
	keywords.put("jmp", .JMP) catch unreachable;
	keywords.put("jlt", .JLT) catch unreachable;
	keywords.put("jgt", .JGT) catch unreachable;
	keywords.put("jeq", .JEQ) catch unreachable;
	keywords.put("jne", .JNE) catch unreachable;
	keywords.put("jle", .JLE) catch unreachable;
	keywords.put("jge", .JGE) catch unreachable;
	keywords.put("ret", .RET) catch unreachable;
	keywords.put("int", .INT) catch unreachable;
	keywords.put("at", .AT) catch unreachable;
	keywords.put("r0", .REG0) catch unreachable;
	keywords.put("r1", .REG1) catch unreachable;
	keywords.put("r2", .REG2) catch unreachable;
	keywords.put("r3", .REG3) catch unreachable;
	keywords.put("r4", .REG4) catch unreachable;
	keywords.put("r5", .REG5) catch unreachable;
	keywords.put("r6", .REG6) catch unreachable;
	keywords.put("r7", .REG7) catch unreachable;
	keywords.put("r8", .REG8) catch unreachable;
	keywords.put("r9", .REG9) catch unreachable;
	keywords.put("r10", .REG10) catch unreachable;
	keywords.put("r11", .REG11) catch unreachable;
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
				tokens.append(token)
					catch unreachable;
				continue;
			}
			_ = std.fmt.parseInt(u64, token.text, 16) catch {
				tokens.append(token)
					catch unreachable;
				continue;
			};
			token.tag = .NUM;
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
	Err,
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
		err.append(set_error(mem, tokens[i].pos, "Unexpected token for beginning of expression, expected (, found {s}", .{tokens[i].text}))
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
		err.append(set_error(mem, tokens[i.*-1].pos, "Unexpected end of file in s expression\n", .{}))
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
			err.append(set_error(mem, tokens[i.*-1].pos, "Unexpected end of file in s expression\n", .{}))
				catch unreachable;
			return ParseError.UnexpectedEOF;
		}
		tok = tokens[i.*];
	}
	i.* += 1;
	return expr;
}

const Bind = struct {
	name: Token,
	args: *Expr,
	expr: *Expr
};

const IRNode = union(enum){
	instruction: ir.Instruction,
	label: Token,
	register: Token,
	interrupt: *Expr
};

const Program = struct {
	binds: Map(Bind),
	mem: *const std.mem.Allocator,
	config: ir.Config,
	vm: Map(*ir.VM),
	global_reif: Reif,
	
	pub fn init(mem: *const std.mem.Allocator) Program {
		const config = ir.Config{
			.screen_width = 1,
			.screen_height = 1,
			.cores = 4,
			.mem_size = 0x100000,
			.mem = mem.*,
		};
		var irmap = Map(*ir.VM).init(mem.*);
		const vm = mem.create(ir.VM)
			catch unreachable;
		vm.* = ir.VM.init(config);
		irmap.put("vm", vm)
			catch unreachable;
		return Program {
			.binds = Map(Bind).init(mem.*),
			.mem=mem,
			.config = config,
			.global_reif = Reif.init(mem),
			.vm = irmap
		};
	}

	pub fn flatten_use(self: *Program, vm_target: Token, subprogram: *Expr, err: *Buffer(Error)) ParseError!void {
		std.debug.assert(subprogram.* == .list);
		for (subprogram.list.items) |subexpr| {
			if (subexpr.* == .list){
				if (subexpr.list.items.len != 0){
					if (subexpr.list.items[0].atom.tag == .BIND){
						const bind = try expr_to_bind(self.mem, subexpr, err);
						self.binds.put(bind.name.text, bind)
							catch unreachable;
					}
					else if (subexpr.list.items[0].atom.tag == .USE){
						const sub = try self.descend(subexpr, vm_target, err);
						try self.flatten_use(vm_target, sub, err);
					}
				}
			}
		}
	}

	pub fn compute(self: *Program, program: Buffer(*Expr), vm_target: Token, err: *Buffer(Error), eval: bool) ParseError!*Expr {
		var old_binds = self.binds.count();
		while (true){
			for (program.items) |expr| {
				if (expr.* == .atom){
					err.append(set_error(self.mem, expr.atom.pos, "Global atom {s}\n", .{expr.atom.text}))
						catch unreachable;
					return ParseError.UnexpectedToken;
				}
				if (expr.list.items.len != 0){
					if (expr.list.items[0].* == .atom){
						if (debug){
							std.debug.print("considering {s}\n", .{expr.list.items[0].atom.text});
						}
						if (expr.list.items[0].atom.tag == .BIND){
							const bind = try expr_to_bind(self.mem, expr, err);
							self.binds.put(bind.name.text, bind)
								catch unreachable;
							if (debug){
								std.debug.print("continuing on bind {s}\n", .{bind.name.text});
							}
							continue;
						}
						else if (expr.list.items[0].atom.tag == .USE){
							const subprogram = try self.descend(expr, vm_target, err);
							try self.flatten_use(vm_target, subprogram, err);
							continue;
						}
					}
					else if (debug){
						std.debug.print("head was not an atom\n", .{});
					}
					const candidate = try self.descend(expr, vm_target, err);
					if (candidate.* == .list){
						if (candidate.list.items.len == 4){
							if (candidate.list.items[0].* == .atom){
								if (candidate.list.items[0].atom.tag == .BIND){
									const bind = try expr_to_bind(self.mem, candidate, err);
									self.binds.put(bind.name.text, bind)
										catch unreachable;
									if (debug){
										std.debug.print("continuing on bind {s} after descend\n", .{bind.name.text});
									}
									continue;
								}
							}
						}
					}
					if (self.binds.count() != old_binds){
						old_binds = self.binds.count();
						continue;
					}
					if (eval){
						if (self.parse_ir(candidate)) |repr| {
							const evaluated = self.evaluate(vm_target, repr);
							if (evaluated.* == .list){
								if (evaluated.list.items.len == 4){
									if (evaluated.list.items[0].* == .atom){
										if (evaluated.list.items[0].atom.tag == .BIND){
											const bind = try expr_to_bind(self.mem, evaluated, err);
											self.binds.put(bind.name.text, bind)
												catch unreachable;
											if (debug){
												std.debug.print("continuing on bind {s} after evaluation\n", .{bind.name.text});
											}
											continue;
										}
									}
								}
							}
							return self.descend(evaluated, vm_target, err);
						}
					}
					return candidate;
				}
			}
		}
	}

	pub fn normalize(self: *Program, normalized: *Buffer(*Expr), expr: *Expr, full: bool) ?*Expr {
		if (expr.* == .list){
			if (expr.list.items.len == 1){
				if (expr.list.items[0].* == .list){
					return self.normalize(normalized, expr.list.items[0], full);
				}
			}
		}
		var limit = expr.list.items.len-1;
		if (full){
			limit += 1;
		}
		for (expr.list.items[0..limit]) |inst| {
			if (inst.* == .atom){
				if (debug){
					std.debug.print("atom in execution block {s}\n", .{inst.atom.text});
				}
				return null;
			}
			if (inst.list.items.len == 0){
				continue;
			}
			if (inst.list.items[0].* == .list){
				const flattened = self.normalize(normalized, inst, true);
				if (flattened == null){
					std.debug.print("could not flatten nested block\n", .{});
					return null;
				}
				continue;
			}
			switch (inst.list.items[0].atom.tag){
				.REG, .LABEL => {
					if (inst.list.items.len != 2){
						std.debug.print("Expected 1 argument for reg or label\n", .{});
						return null;
					}
					if (self.expect_token(normalized, &inst.list.items[1])){
						normalized.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Expected token for reg or label\n", .{});
					return null;
				},
				.REIF => {
					if (inst.list.items.len != 3){
						std.debug.print("Expected 2 arguments for reif\n", .{});
						return null;
					}
					if (self.expect_register(normalized, &inst.list.items[1])){
						if (inst.list.items[2].* == .atom){
							if (inst.list.items[2].atom.tag == .NUM){
								normalized.append(inst)
									catch unreachable;
								continue;
							}
						}
						const adr = self.global_reif.add_relation(inst.list.items[2]);
						const buf = self.mem.alloc(u8, 20)
							catch unreachable;
						const s = std.fmt.bufPrint(buf, "{x}", .{adr})
							catch unreachable;
						const loc = self.mem.create(Expr)
							catch unreachable;
						loc.* = Expr{
							.atom = Token{
								.pos = 0,
								.text = s,
								.tag = .NUM
							}
						};
						inst.list.items[2] = loc;
						normalized.append(inst)
							catch unreachable;
						continue;
					}
				},
				.MOV => {
					if (inst.list.items.len != 3){
						std.debug.print("Expected 2 arguments for mov\n", .{});
						return null;
					}
					if (self.expect_register(normalized, &inst.list.items[1])){
						if (self.expect_dregister(normalized, inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (self.expect_register(normalized, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (self.expect_token(normalized, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						std.debug.print("mov unable to match second argument\n", .{});
						return null;
					}
					if (self.expect_dregister(normalized, inst.list.items[1])){
						if (self.expect_dregister(normalized, inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (self.expect_register(normalized, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (self.expect_token(normalized, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						std.debug.print("mov unable to match second argument\n", .{});
						return null;
					}
					std.debug.print("mov unable to match first argument\n", .{});
					return null;
				},
				.ADD, .SUB, .MUL, .DIV, .MOD, .UADD, .USUB, .UMUL, .UDIV, .UMOD, .SHR, .SHL, .AND, .OR, .XOR => {
					if (inst.list.items.len != 4){
						std.debug.print("Expected 3 arguments for binary alu operation\n", .{});
						return null;
					}
					if (self.expect_register(normalized, &inst.list.items[1])){
						if (self.expect_alu_arg(normalized, &inst.list.items[2])){
							if (self.expect_alu_arg(normalized, &inst.list.items[3])){
								normalized.append(inst)
									catch unreachable;
								continue;
							}
						}
					}
					std.debug.print("Unable to match arguments on binary alu operation\n", .{});
					return null;
				},
				.NOT, .COM, .CMP=> {
					if (inst.list.items.len != 3){
						std.debug.print("Expected 2 arguments for unary alu operation\n", .{});
						return null;
					}
					if (self.expect_register(normalized, &inst.list.items[1])){
						if (self.expect_alu_arg(normalized, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
					}
					std.debug.print("Unable to match arguments on unary alu operation\n", .{});
					return null;
				},
				.JMP, .JEQ, .JNE, .JGT, .JGE, .JLT, .JLE, .CALL => {
					if (inst.list.items.len != 2){
						std.debug.print("jump or call expected target\n", .{});
						return null;
					}
					if (self.expect_token(normalized, &inst.list.items[1])){
						normalized.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Unable to match argument for jump or call\n", .{});
					return null;
				},
				.RET => {
					if (inst.list.items.len != 2){
						std.debug.print("Expected argument for ret\n", .{});
						return null;
					}
					if (self.expect_alu_arg(normalized, &inst.list.items[1])){
						normalized.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Unable to match argument for ret\n", .{});
					return null;
				},
				.PSH, .POP => {
					if (inst.list.items.len != 2){
						std.debug.print("Expected argument for push or pop\n", .{});
						return null;
					}
					if (self.expect_register(normalized, &inst.list.items[1])){
						normalized.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Unable to match argument for push or pop\n", .{});
					return null;
				},
				.INT => {
					normalized.append(inst)
						catch unreachable;
					continue;
				},
				else => {
					std.debug.print("Unknown opcode {s}\n", .{inst.list.items[0].atom.text});
					return null;
				}
			}
		}
		if (expr.list.items[expr.list.items.len-1].* == .atom){
			return expr.list.items[expr.list.items.len-1];
		}
		if (expr.list.items[expr.list.items.len-1].list.items[0].* == .list){
			return self.normalize(normalized, expr.list.items[expr.list.items.len-1].list.items[0], false);
		}
		return expr.list.items[expr.list.items.len-1].list.items[0];
	}

	pub fn parse_ir(self: *Program, programexpr: *Expr) ?ReifableRepr {
		if (programexpr.* == .atom){
			std.debug.print("cannot parse atom {s}\n", .{programexpr.atom.text});
			return null;
		}
		if (programexpr.list.items.len == 0){
			std.debug.print("cannot parse empty expression\n", .{});
			return null;
		}
		if (debug){
			std.debug.print("Normalizing target: \n", .{});
			show_expr(programexpr, 1);
			std.debug.print("\n", .{});
		}
		var normalized = Buffer(*Expr).init(self.mem.*);
		if (self.normalize(&normalized, programexpr, true) == null){
			std.debug.print("Failed normalization parse\n", .{});
			return null;
		}
		if (debug){
			std.debug.print("Normalized:\n", .{});
			for (normalized.items) |e| {
				show_expr(e, 1);
				std.debug.print("\n", .{});
			}
			std.debug.print("\n", .{});
		}
		normalized = self.color_cfg(&normalized);
		if (debug){
			std.debug.print("Colored:\n", .{});
			for (normalized.items) |e| {
				show_expr(e, 1);
				std.debug.print("\n", .{});
			}
			std.debug.print("\n", .{});
		}
		self.flatten_interrupts(&normalized);
		if (debug){
			std.debug.print("Flattened interrupts:\n", .{});
			for(normalized.items) |e| {
				show_expr(e, 1);
				std.debug.print("\n", .{});
			}
			std.debug.print("\n", .{});
		}
		self.inscribe_labels(&normalized);
		if (debug){
			std.debug.print("Inscribed labels:\n", .{});
			for(normalized.items) |e| {
				show_expr(e, 1);
				std.debug.print("\n", .{});
			}
			std.debug.print("\n", .{});
		}
		var parsed = Buffer(ir.Instruction).init(self.mem.*);
		var i: u64 = 0;
		while (i < normalized.items.len) : (i += 1){
			const expr = normalized.items[i];
			switch (expr.list.items[0].atom.tag){
				.MOV => {
					if (is_register(expr.list.items[1])) |dest| {
						if (is_register(expr.list.items[2])) |src| {
							const inst = ir.Instruction{
								.tag = ir.TOKEN.MOV,
								.data = .{
									.move = .{
										.dest = ir.LArg{
											.register = dest
										},
										.src = ir.RArg{
											.register = src
										}
									}
								}
							};
							parsed.append(inst)
								catch unreachable;
							continue;
						}
						if (is_dregister(expr.list.items[2])) |src| {
							const inst = ir.Instruction{
								.tag = ir.TOKEN.MOV,
								.data = .{
									.move = .{
										.dest = ir.LArg{
											.register = dest
										},
										.src = ir.RArg{
											.dregister = src
										}
									}
								}
							};
							parsed.append(inst)
								catch unreachable;
							continue;
						}
						else if (is_literal(expr.list.items[2])) |src| {
							const inst = ir.Instruction{
								.tag = ir.TOKEN.MOV,
								.data = .{
									.move = .{
										.dest = ir.LArg{
											.register = dest
										},
										.src = ir.RArg{
											.literal = src
										}
									}
								}
							};
							parsed.append(inst)
								catch unreachable;
							continue;
						}
					}
					if (is_dregister(expr.list.items[1])) |dest| {
						if (is_register(expr.list.items[2])) |src| {
							const inst = ir.Instruction{
								.tag = ir.TOKEN.MOV,
								.data = .{
									.move = .{
										.dest = ir.LArg{
											.dregister = dest
										},
										.src = ir.RArg{
											.register = src
										}
									}
								}
							};
							parsed.append(inst)
								catch unreachable;
							continue;
						}
						if (is_dregister(expr.list.items[2])) |src| {
							const inst = ir.Instruction{
								.tag = ir.TOKEN.MOV,
								.data = .{
									.move = .{
										.dest = ir.LArg{
											.dregister = dest
										},
										.src = ir.RArg{
											.dregister = src
										}
									}
								}
							};
							parsed.append(inst)
								catch unreachable;
							continue;
						}
						else if (is_literal(expr.list.items[2])) |src| {
							const inst = ir.Instruction{
								.tag = ir.TOKEN.MOV,
								.data = .{
									.move = .{
										.dest = ir.LArg{
											.dregister = dest
										},
										.src = ir.RArg{
											.literal = src
										}
									}
								}
							};
							parsed.append(inst)
								catch unreachable;
							continue;
						}
					}
					std.debug.print("Invalid mov args\n", .{});
					return null;
				},
				.ADD, .SUB, .MUL, .DIV, .MOD, .UADD, .USUB, .UMUL, .UDIV, .UMOD, .SHR, .SHL, .AND, .OR, .XOR => {
					if (is_register(expr.list.items[1])) |dest| {
						if (is_alu_arg(expr.list.items[2])) |left| {
							if (is_alu_arg(expr.list.items[3])) |right| {
								const inst = ir.Instruction{
									.tag = translate_tag(expr.list.items[0].atom.tag),
									.data = .{
										.alu_bin = .{
											.dest = dest,
											.left = left,
											.right = right
										}
									}
								};
								parsed.append(inst)
									catch unreachable;
								continue;
							}
						}
					}
					std.debug.print("Invalid binary alu args for instruction {s}\n", .{expr.list.items[0].atom.text});
					return null;
				},
				.NOT, .COM => {
					if (is_register(expr.list.items[1])) |dest| {
						if (is_alu_arg(expr.list.items[2])) |src| {
							const inst = ir.Instruction {
								.tag = translate_tag(expr.list.items[0].atom.tag),
								.data = .{
									.alu_un = .{
										.dest = dest,
										.src = src
									}
								}
							};
							parsed.append(inst)
								catch unreachable;
							continue;
						}
					}
					std.debug.print("Invalid unary alu args\n", .{});
					return null;
				},
				.CMP => {
					if (is_register(expr.list.items[1])) |dest| {
						if (is_alu_arg(expr.list.items[2])) |src| {
							const inst = ir.Instruction {
								.tag = translate_tag(expr.list.items[0].atom.tag),
								.data = .{
									.compare = .{
										.left = dest,
										.right = src
									}
								}
							};
							parsed.append(inst)
								catch unreachable;
							continue;
						}
					}
					std.debug.print("Invalid compare args\n", .{});
					return null;
				},
				.JMP, .JEQ, .JNE, .JGT, .JGE, .JLT, .JLE => {
					if (is_literal(expr.list.items[1])) |lit| {
						const inst = ir.Instruction{
							.tag = translate_tag(expr.list.items[0].atom.tag),
							.data = .{
								.jump = lit
							}
						};
						parsed.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Invalid jump args\n", .{});
					return null;
				},
				.CALL => {
					if (is_literal(expr.list.items[1])) |lit| {
						const inst = ir.Instruction{
							.tag = translate_tag(expr.list.items[0].atom.tag),
							.data = .{
								.call = lit
							}
						};
						parsed.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Invalid call args\n", .{});
					return null;
				},
				.RET => {
					if (is_alu_arg(expr.list.items[1])) |val| {
						const inst = ir.Instruction{
							.tag = translate_tag(expr.list.items[0].atom.tag),
							.data = .{
								.ret = val
							}
						};
						parsed.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Invalid return args\n", .{});
					return null;
				},
				.PSH => {
					if (is_register(expr.list.items[1])) |src| {
						const inst = ir.Instruction{
							.tag = translate_tag(expr.list.items[0].atom.tag),
							.data = .{
								.push = src
							}
						};
						parsed.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Invalid push args\n", .{});
					return null;
				},
				.POP => {
					if (is_register(expr.list.items[1])) |src| {
						const inst = ir.Instruction{
							.tag = translate_tag(expr.list.items[0].atom.tag),
							.data = .{
								.pop = src
							}
						};
						parsed.append(inst)
							catch unreachable;
						continue;
					}
					std.debug.print("Invalid pop args\n", .{});
					return null;
				},
				.INT => {
					parsed.append(ir.Instruction{
						.tag = ir.TOKEN.INT,
						.data = .{
							.interrupt = undefined
						}
					}) catch unreachable;
					continue;
				},
				else => {
					std.debug.print("Invalid opcode {s}\n", .{expr.list.items[0].atom.text});
					return null;
				}
			}
		}
		return ReifableRepr{
			.parsed = parsed,
			.reif = self.global_reif
		};
	}

	pub fn prepend_reif(self: *Program, normalized: *Buffer(*Expr)) void {
		var i: u64 = 0;
		const reif = self.mem.create(Expr)
			catch unreachable;
		reif.* = Expr{
			.atom = Token{
				.pos = 0,
				.tag = .REIF,
				.text = self.mem.dupe(u8, "reif") catch unreachable
			}
		};
		const reg = self.mem.create(Expr)
			catch unreachable;
		reg.* = Expr{
			.atom = Token{
				.pos = 0,
				.tag = .REG0,
				.text = self.mem.dupe(u8, "r0") catch unreachable
			}
		};
		const addinst = self.mem.create(Expr)
			catch unreachable;
		addinst.* = Expr{
			.atom = Token{
				.pos = 0,
				.tag = .ADD,
				.text = self.mem.dupe(u8, "add") catch unreachable
			}
		};
		const mov = self.mem.create(Expr)
			catch unreachable;
		mov.* = Expr{
			.atom = Token{
				.pos = 0,
				.tag = .MOV,
				.text = self.mem.dupe(u8, "mov") catch unreachable
			}
		};
		const at = self.mem.create(Expr)
			catch unreachable;
		at.* = Expr{
			.atom = Token{
				.pos = 0,
				.tag = .AT,
				.text = self.mem.dupe(u8, "at") catch unreachable
			}
		};
		const zero = self.mem.create(Expr)
			catch unreachable;
		zero.* = Expr{
			.atom = Token{
				.pos = 0,
				.tag = .NUM,
				.text = self.mem.dupe(u8, "0") catch unreachable
			}
		};
		const eight = self.mem.create(Expr)
			catch unreachable;
		eight.* = Expr{
			.atom = Token{
				.pos = 0,
				.tag = .NUM,
				.text = self.mem.dupe(u8, "8") catch unreachable
			}
		};
		const dereg = self.mem.create(Expr)
			catch unreachable;
		dereg.* = Expr{
			.atom = Token{
				.pos = 0,
				.tag = .REG1,
				.text = self.mem.dupe(u8, "r1") catch unreachable
			}
		};
		const deref = self.mem.create(Expr)
			catch unreachable;
		deref.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		deref.list.append(at)
			catch unreachable;
		deref.list.append(dereg)
			catch unreachable;
		const setup = self.mem.create(Expr)
			catch unreachable;
		setup.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		setup.list.append(mov)
			catch unreachable;
		setup.list.append(dereg)
			catch unreachable;
		setup.list.append(zero)
			catch unreachable;
		normalized.insert(i, setup)
			catch unreachable;
		i += 1;
		for (self.global_reif.static.items) |wordslice| {
			for (wordslice) |word| {
				const inst = self.mem.create(Expr)
					catch unreachable;
				inst.* = Expr{
					.list = Buffer(*Expr).init(self.mem.*)
				};
				const semiexpr = self.mem.create(Expr)
					catch unreachable;
				const buf = self.mem.alloc(u8, 20)
					catch unreachable;
				const slice = std.fmt.bufPrint(buf, "{x}", .{word})
					catch unreachable;
				semiexpr.* = Expr{
					.atom = Token{
						.pos = 0,
						.tag = .NUM,
						.text = slice
					}
				};
				inst.list.append(reif)
					catch unreachable;
				inst.list.append(reg)
					catch unreachable;
				inst.list.append(semiexpr)
					catch unreachable;
				normalized.insert(i, inst)
					catch unreachable;
				i += 1;
				const write = self.mem.create(Expr)
					catch unreachable;
				write.* = Expr{
					.list = Buffer(*Expr).init(self.mem.*)
				};
				write.list.append(mov)
					catch unreachable;
				write.list.append(deref)
					catch unreachable;
				write.list.append(reg)
					catch unreachable;
				normalized.insert(i, write)
					catch unreachable;
				i += 1;
				const add = self.mem.create(Expr)
					catch unreachable;
				add.* = Expr{
					.list = Buffer(*Expr).init(self.mem.*)
				};
				add.list.append(addinst)
					catch unreachable;
				add.list.append(dereg)
					catch unreachable;
				add.list.append(dereg)
					catch unreachable;
				add.list.append(eight)
					catch unreachable;
				normalized.insert(i, add)
					catch unreachable;
				i += 1;
			}
		}
	}

	pub fn inscribe_labels(self: *Program, normalized: *Buffer(*Expr)) void {
		var i: u64 = 0;
		var chainmap = Map(LabelChain).init(self.mem.*);
		while (i < normalized.items.len){
			const expr = normalized.items[i];
			switch (expr.list.items[0].atom.tag){
				.JMP, .JEQ, .JNE, .JLE, .JGE, .JLT, .JGT, .CALL => {
					if (expr.list.items[1].atom.tag == .NUM){
						i += 1;
						continue;
					}
					const key = self.mem.dupe(u8, expr.list.items[1].atom.text)
						catch unreachable;
					if (chainmap.getPtr(key)) |link| {
						if (link.* == .waiting){
							expr.list.items[1].atom.pos = i;
							link.waiting.append(&expr.list.items[1])
								catch unreachable;
						}
						else if (link.* == .fulfilled){
							const offset:i16 = @bitCast(@as(u16, @truncate(link.fulfilled.atom.pos)));
							const current: i16 = @bitCast(@as(u16, @truncate(i)));
							const buf = self.mem.alloc(u8, 20)
								catch unreachable;
							const slice = std.fmt.bufPrint(buf, "{x}", .{@as(u16, @bitCast(offset -% current))})
								catch unreachable;
							const loc = self.mem.create(Expr)
								catch unreachable;
							loc.* = Expr{
								.atom=Token{
									.pos = i,
									.text = slice,
									.tag=.NUM,
								},
							};
							expr.list.items[1] = loc;
						}
					}
					else{
						var newchain = LabelChain{
							.waiting = Buffer(**Expr).init(self.mem.*)
						};
						expr.list.items[1].atom.pos = i;
						newchain.waiting.append(&expr.list.items[1])
							catch unreachable;
						chainmap.put(key, newchain)
							catch unreachable;
					}
					i += 1;
					continue;
				},
				.LABEL => {
					const buf = self.mem.alloc(u8, 20)
						catch unreachable;
					const slice = std.fmt.bufPrint(buf, "{x}", .{i})
						catch unreachable;
					const replacement = self.mem.create(Expr)
						catch unreachable;
					replacement.* = Expr{
						.atom = Token{
							.pos = i,
							.text = slice,
							.tag = .NUM
						}
					};
					const key = self.mem.dupe(u8, expr.list.items[1].atom.text)
						catch unreachable;
					if (chainmap.get(key)) |link| {
						if (link == .waiting){
							for (link.waiting.items) |entry| {
								const replacebuf = self.mem.alloc(u8, 20)
									catch unreachable;
								const offset:i16 = @bitCast(@as(u16, @truncate(entry.*.atom.pos)));
								const current: i16 = @bitCast(@as(u16, @truncate(i)));
								const replaceslice = std.fmt.bufPrint(replacebuf, "{x}", .{@as(u16, @bitCast(current-%offset))})
									catch unreachable;
								entry.* = self.mem.create(Expr)
									catch unreachable;
								entry.*.* = Expr{
									.atom = Token{
										.pos = i,
										.text = replaceslice,
										.tag = .NUM
									}
								};
							}
						}
					}
					chainmap.put(key, LabelChain{
						.fulfilled = replacement
					}) catch unreachable;
					_ = normalized.orderedRemove(i);
					continue;
				},
				.REG => {
					_ = normalized.orderedRemove(i);
					continue;
				},
				else => {
					i += 1;
					continue;
				}
			}
		}
		var it = chainmap.iterator();
		while (it.next()) |entry| {
			if (entry.value_ptr.* != .fulfilled){
				std.debug.print("Unfulfilled label jump {s}\n", .{entry.key_ptr.*});
				std.debug.assert(false);
			}
		}
	}

	pub fn flatten_interrupts(self: *Program, normalized: *Buffer(*Expr)) void {
		var i: u64 = 0;
		while (i < normalized.items.len) : (i += 1) {
			const expr = normalized.items[i];
			std.debug.assert(expr.* == .list);
			std.debug.assert(expr.list.items[0].* == .atom);
			switch(expr.list.items[0].atom.tag){
				.REIF => {
					const clear = self.mem.create(Expr)
						catch unreachable;
					clear.* = Expr{
						.list = Buffer(*Expr).init(self.mem.*)
					};
					const movop = self.mem.create(Expr)
						catch unreachable;
					movop.* = Expr{
						.atom = Token{
							.pos = 0,
							.tag = .MOV,
							.text = self.mem.dupe(u8, "mov") catch unreachable
						}
					};
					const movreg = self.mem.create(Expr)
						catch unreachable;
					movreg.* = expr.list.items[1].*;
					const zero = self.mem.create(Expr)
						catch unreachable;
					zero.* = Expr{
						.atom = Token{
							.pos = 0,
							.tag = .NUM,
							.text = self.mem.dupe(u8, "0") catch unreachable
						}
					};
					clear.list.append(movop)
						catch unreachable;
					clear.list.append(movreg)
						catch unreachable;
					clear.list.append(zero)
						catch unreachable;
					normalized.insert(i, clear)
						catch unreachable;
					i += 1;
					const large = std.fmt.parseInt(u64, expr.list.items[2].atom.text, 16)
						catch unreachable;
					for (0..8) |byte| {
						var loc = self.mem.create(Expr)
							catch unreachable;
						loc.* = Expr{
							.list = Buffer(*Expr).init(self.mem.*)
						};
						var op = self.mem.create(Expr)
							catch unreachable;
						op.* = Expr{
							.atom = Token{
								.pos = 0,
								.tag=.OR,
								.text=self.mem.dupe(u8, "or") catch unreachable
							}
						};
						var reg = self.mem.create(Expr)
							catch unreachable;
						reg.* = expr.list.items[1].*;
						var segment = self.mem.create(Expr)
							catch unreachable;
						const buf = self.mem.alloc(u8, 8)
							catch unreachable;
						const slice = std.fmt.bufPrint(buf, "{x}", .{(large >> @truncate((7-byte)*8))&0xff})
							catch unreachable;
						segment.* = Expr{
							.atom = Token{
								.pos = 0,
								.tag=.NUM,
								.text=slice
							}
						};
						loc.list.append(op)
							catch unreachable;
						loc.list.append(reg)
							catch unreachable;
						loc.list.append(reg)
							catch unreachable;
						loc.list.append(segment)
							catch unreachable;
						normalized.insert(i, loc)
							catch unreachable;
						i += 1;
						if (byte == 7){
							break;
						}
						loc = self.mem.create(Expr)
							catch unreachable;
						loc.* = Expr{
							.list = Buffer(*Expr).init(self.mem.*)
						};
						op = self.mem.create(Expr)
							catch unreachable;
						op.* = Expr{
							.atom = Token{
								.pos = 0,
								.tag=.SHL,
								.text=self.mem.dupe(u8, "shl") catch unreachable
							}
						};
						reg = self.mem.create(Expr)
							catch unreachable;
						reg.* = expr.list.items[1].*;
						segment = self.mem.create(Expr)
							catch unreachable;
						segment.* = Expr{
							.atom = Token{
								.pos = 0,
								.tag=.NUM,
								.text=self.mem.dupe(u8, "8")
									catch unreachable
							}
						};
						loc.list.append(op)
							catch unreachable;
						loc.list.append(reg)
							catch unreachable;
						loc.list.append(reg)
							catch unreachable;
						loc.list.append(segment)
							catch unreachable;
						normalized.insert(i, loc)
							catch unreachable;
						i += 1;
					}
					_ = normalized.orderedRemove(i);
					i -= 1;
				},
				.INT => {
					std.debug.assert(expr.list.items.len < 5);
					switch (expr.list.items.len){
						2 => {
							self.move_argument_register(normalized, &i, .REG0, expr.list.items[1]);
						},
						3 => {
							self.move_argument_register(normalized, &i, .REG0, expr.list.items[1]);
							self.move_argument_register(normalized, &i, .REG1, expr.list.items[2]);
						},
						4 => {
							self.move_argument_register(normalized, &i, .REG0, expr.list.items[1]);
							self.move_argument_register(normalized, &i, .REG1, expr.list.items[2]);
							self.move_argument_register(normalized, &i, .REG2, expr.list.items[3]);
						},
						else => {
							unreachable;
						}
					}
				},
				else => {
					continue;
				}
			}
		}
	}

	pub fn move_argument_register(self: *Program, normalized: *Buffer(*Expr), i: *u64, register: TOKEN, source: *Expr) void {
		if (source.* == .atom){
			if (source.atom.tag == register){
				return;
			}
			const loc = self.mem.create(Expr)
				catch unreachable;
			loc.* = Expr{
				.list = Buffer(*Expr).init(self.mem.*)
			};
			const op = self.mem.create(Expr)
				catch unreachable;
			op.* = Expr{
				.atom = Token{
					.text = self.mem.dupe(u8, "mov") catch unreachable,
					.pos = 0,
					.tag = .MOV
				}
			};
			const dest = self.mem.create(Expr)
				catch unreachable;
			dest.* = Expr{
				.atom = Token{
					.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
					.pos = 0,
					.tag = register
				}
			};
			loc.list.append(op)
				catch unreachable;
			loc.list.append(dest)
				catch unreachable;
			loc.list.append(source)
				catch unreachable;
			normalized.insert(i.*, loc)
				catch unreachable;
			i.* += 1;
			return;
		}
		if (source.* == .list){
			std.debug.assert(source.list.items[0].* == .atom);
			std.debug.assert(source.list.items[0].atom.tag == .AT);
			std.debug.assert(source.list.items[1].* == .atom);
			if ((source.list.items[1].atom.tag == register) or
			  ( source.list.items[1].atom.tag != .REG4 and
			  source.list.items[1].atom.tag != .REG5 and
			  source.list.items[1].atom.tag != .REG6 and
			  source.list.items[1].atom.tag != .REG7 and
			  source.list.items[1].atom.tag != .REG8 and
			  source.list.items[1].atom.tag != .REG9 and
			  source.list.items[1].atom.tag != .REG10)){
				const loc = self.mem.create(Expr)
					catch unreachable;
				loc.* = Expr{
					.list = Buffer(*Expr).init(self.mem.*)
				};
				const op = self.mem.create(Expr)
					catch unreachable;
				op.* = Expr{
					.atom = Token{
						.text = self.mem.dupe(u8, "mov") catch unreachable,
						.pos = 0,
						.tag = .MOV
					}
				};
				const dest = self.mem.create(Expr)
					catch unreachable;
				dest.* = Expr{
					.atom = Token{
						.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
						.pos = 0,
						.tag = register
					}
				};
				loc.list.append(op)
					catch unreachable;
				loc.list.append(dest)
					catch unreachable;
				loc.list.append(source)
					catch unreachable;
				normalized.insert(i.*, loc)
					catch unreachable;
				i.* += 1;
				return;
			}
		}
		var loc = self.mem.create(Expr)
			catch unreachable;
		loc.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		var op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "mov") catch unreachable,
				.pos = 0,
				.tag = .MOV
			}
		};
		var dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
				.pos = 0,
				.tag = register
			}
		};
		var src = self.mem.create(Expr)
			catch unreachable;
		src.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "sp") catch unreachable,
				.pos = 0,
				.tag = .SPTR
			}
		};
		loc.list.append(op)
			catch unreachable;
		loc.list.append(dest)
			catch unreachable;
		loc.list.append(src)
			catch unreachable;
		normalized.insert(i.*, loc)
			catch unreachable;
		i.* += 1;
		loc = self.mem.create(Expr)
			catch unreachable;
		loc.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "add") catch unreachable,
				.pos = 0,
				.tag = .ADD
			}
		};
		dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
				.pos = 0,
				.tag = register
			}
		};
		src = self.mem.create(Expr)
			catch unreachable;
		var text = self.mem.dupe(u8, "0")
			catch unreachable;
		if (register == .REG1){
			text = self.mem.dupe(u8, "8")
				catch unreachable;
		}
		else if (register == .REG2){
			text = self.mem.dupe(u8, "10")
				catch unreachable;
		}
		else if (register == .REG3){
			text = self.mem.dupe(u8, "18")
				catch unreachable;
		}
		else if (register == .REG4){
			text = self.mem.dupe(u8, "20")
				catch unreachable;
		}
		else if (register == .REG5){
			text = self.mem.dupe(u8, "28")
				catch unreachable;
		}
		else if (register == .REG6){
			text = self.mem.dupe(u8, "30")
				catch unreachable;
		}
		else if (register == .REG7){
			text = self.mem.dupe(u8, "38")
				catch unreachable;
		}
		else if (register == .REG8){
			text = self.mem.dupe(u8, "40")
				catch unreachable;
		}
		else if (register == .REG9){
			text = self.mem.dupe(u8, "48")
				catch unreachable;
		}
		src.* = Expr{
			.atom = Token{
				.text = text,
				.pos = 0,
				.tag = .NUM
			}
		};
		loc.list.append(op)
			catch unreachable;
		loc.list.append(dest)
			catch unreachable;
		loc.list.append(dest)
			catch unreachable;
		loc.list.append(src)
			catch unreachable;
		normalized.insert(i.*, loc)
			catch unreachable;
		i.* += 1;
		loc = self.mem.create(Expr)
			catch unreachable;
		loc.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "mov") catch unreachable,
				.pos = 0,
				.tag = .MOV
			}
		};
		dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
				.pos = 0,
				.tag = register
			}
		};
		src = self.mem.create(Expr)
			catch unreachable;
		src.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		const at = self.mem.create(Expr)
			catch unreachable;
		at.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "at") catch unreachable,
				.pos = 0,
				.tag = .AT
			}
		};
		src.list.append(at)
			catch unreachable;
		src.list.append(dest)
			catch unreachable;
		loc.list.append(op)
			catch unreachable;
		loc.list.append(dest)
			catch unreachable;
		loc.list.append(src)
			catch unreachable;
		normalized.insert(i.*, loc)
			catch unreachable;
		i.* += 1;
	}

	pub fn pop_register(self: Program, normalized: *Buffer(*Expr), i: u64, register: TOKEN) void {
		const push = self.mem.create(Expr)
			catch unreachable;
		push.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		const op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "pop") catch unreachable,
				.pos = 0,
				.tag = .POP
			}
		};
		const src = self.mem.create(Expr)
			catch unreachable;
		src.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
				.pos = 0,
				.tag = register
			}
		};
		push.list.append(op)
			catch unreachable;
		push.list.append(src)
			catch unreachable;
		normalized.insert(i, push)
			catch unreachable;
	}

	pub fn push_register(self: Program, normalized: *Buffer(*Expr), i: u64, register: TOKEN) void {
		const push = self.mem.create(Expr)
			catch unreachable;
		push.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		const op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "psh") catch unreachable,
				.pos = 0,
				.tag = .PSH
			}
		};
		const src = self.mem.create(Expr)
			catch unreachable;
		src.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
				.pos = 0,
				.tag = register
			}
		};
		push.list.append(op)
			catch unreachable;
		push.list.append(src)
			catch unreachable;
		normalized.insert(i, push)
			catch unreachable;
	}

	pub fn expect_alu_arg(self: *Program, normalized: *Buffer(*Expr), expr: **Expr) bool {
		return (self.expect_register(normalized, expr) or self.expect_token(normalized, expr));
	}

	pub fn expect_register(self: *Program, normalized: *Buffer(*Expr), expr: **Expr) bool {
		return self.expect_token(normalized, expr);
	}

	pub fn expect_dregister(self: *Program, normalized: *Buffer(*Expr), expr: *Expr) bool {
		if (expr.* == .atom){
			return false;
		}
		if (expr.list.items.len != 2){
			return false;
		}
		if (self.expect_register(normalized, &expr.list.items[1])){
			return true;
		}
		if (self.normalize(normalized, expr.list.items[1], false)) |norm| {
			expr.list.items[1] = norm;
			return self.expect_register(normalized, &expr.list.items[1]);
		}
		return false;
	}

	pub fn expect_token(self: *Program, normalized: *Buffer(*Expr), expr: **Expr) bool {
		if (expr.*.* == .list){
			if (self.normalize(normalized, expr.*, false)) |norm| {
				expr.* = norm;
				return true;
			}
			return false;
		}
		if (expr.*.atom.tag == .STR){
			return false;
		}
		return true;
	}

	pub fn color_cfg(self: *Program, normalized: *Buffer(*Expr)) Buffer(*Expr) {
		var block_map = Map(*BBlock).init(self.mem.*);
		var block_chain = Map(Buffer(*BBlock)).init(self.mem.*);
		var i: u64 = 0;
		var current_block = BBlock.init(self.mem, i);
		var block_list = Buffer(*BBlock).init(self.mem.*);
		block_list.append(current_block)
			catch unreachable;
		while (i < normalized.items.len){
			const expr = normalized.items[i];
			switch (expr.list.items[0].atom.tag){
				.LABEL => {
					if (current_block.start != i){
						current_block.end = i-1;
						const next_block = BBlock.init(self.mem, i);
						current_block.next.append(next_block)
							catch unreachable;
						next_block.prev.append(current_block)
							catch unreachable;
						current_block = next_block;
						block_list.append(current_block)
							catch unreachable;
					}
					if (block_chain.get(expr.list.items[1].atom.text)) |chain| {
						for (chain.items) |block| {
							block.next.append(current_block)
								catch unreachable;
							current_block.prev.append(block)
								catch unreachable;
						}
						_ = block_chain.remove(expr.list.items[1].atom.text);
					}
					block_map.put(expr.list.items[1].atom.text, current_block)
						catch unreachable;
				},
				.JMP => {
					current_block.end = i;
					const next_block = BBlock.init(self.mem, i+1);
					if (block_map.get(expr.list.items[1].atom.text)) |exists| {
						current_block.next.append(exists)
							catch unreachable;
						exists.prev.append(current_block)
							catch unreachable;
					}
					else if (block_chain.getPtr(expr.list.items[1].atom.text)) |buffer| {
						buffer.append(current_block)
							catch unreachable;
					}
					else {
						var buf = Buffer(*BBlock).init(self.mem.*);
						buf.append(current_block)
							catch unreachable;
						block_chain.put(expr.list.items[1].atom.text, buf)
							catch unreachable;
					}
					current_block = next_block;
					block_list.append(current_block)
						catch unreachable;
				},
				.JEQ, .JNE, .JGT, .JGE, .JLT, .JLE => {
					current_block.end = i;
					const next_block = BBlock.init(self.mem, i+1);
					if (block_map.get(expr.list.items[1].atom.text)) |exists| {
						current_block.next.append(exists)
							catch unreachable;
						exists.prev.append(current_block)
							catch unreachable;
					}
					else if (block_chain.getPtr(expr.list.items[1].atom.text)) |buffer| {
						buffer.append(current_block)
							catch unreachable;
					}
					current_block.next.append(next_block)
						catch unreachable;
					next_block.prev.append(current_block)
						catch unreachable;
					current_block = next_block;
					block_list.append(current_block)
						catch unreachable;
				},
				.RET => {
					current_block.end = i;
					const next_block = BBlock.init(self.mem, i+1);
					current_block.next.append(next_block)
						catch unreachable;
					next_block.prev.append(current_block)
						catch unreachable;
					current_block = next_block;
					block_list.append(current_block)
						catch unreachable;
				},
				.MOV => {
					self.check_var_write(current_block, expr.list.items[1]);
					self.check_var_read(current_block, expr.list.items[2]);
				},
				.ADD, .SUB, .MUL, .DIV, .MOD, .UADD, .USUB, .UMUL, .UDIV, .UMOD, .SHR, .SHL, .AND, .OR, .XOR => {
					self.check_var_write(current_block, expr.list.items[1]);
					self.check_var_read(current_block, expr.list.items[2]);
					self.check_var_read(current_block, expr.list.items[3]);
				},
				.NOT, .COM => {
					self.check_var_write(current_block, expr.list.items[1]);
					self.check_var_read(current_block, expr.list.items[2]);
				},
				.CMP => {
					self.check_var_read(current_block, expr.list.items[1]);
					self.check_var_read(current_block, expr.list.items[2]);
				},
				.PSH => {
					self.check_var_read(current_block, expr.list.items[1]);
				},
				.POP => {
					self.check_var_write(current_block, expr.list.items[1]);
				},
				.REIF => {
					self.check_var_write(current_block, expr.list.items[1]);
				},
				.INT => {
					for (expr.list.items[1..expr.list.items.len]) |arg| {
						self.check_var_read(current_block, arg);
					}
				},
				else => {}
			}
			i += 1;
		}
		current_block.end = i;
		var visited = std.AutoHashMap(*BBlock, bool).init(self.mem.*);
		while (self.backward_dfs_cfg(current_block, &visited)) {
			visited.clearRetainingCapacity();
		}
		var new = Buffer(*Expr).init(self.mem.*);
		var stack_offsets = Map(u64).init(self.mem.*);
		var stack_position: u64 = 0; //TODO we'll try just making it global for now, we should run through in chronological order? I still dont know how im realistically suposed to track runtime stack values without storing them in another specially handled register
		for (block_list.items) |block| {
			var live_after = Buffer(Buffer(*Expr)).init(self.mem.*);
			var back = block.end;
			var last = true;
			while (back > block.start){
				const inst = normalized.items[back-1];
				back -= 1;
				var after = Buffer(*Expr).init(self.mem.*);
				switch (inst.list.items[0].atom.tag){
					.MOV, .NOT, .COM => {
						if (!last){
							if (targets_reg(inst.list.items[1])) |dest| {
								for (live_after.items[0].items) |live| {
									if (!std.mem.eql(u8, live.atom.text, dest.atom.text)){
										after.append(live)
											catch unreachable;
									}
								}
							}
						}
						else{
							last = false;
							for (block.live_out.items)|out| {
								after.append(out)
									catch unreachable;
							}
						}
						if (targets_reg(inst.list.items[2])) |src| {
							after.append(src)
								catch unreachable;
						}
					},
					.ADD, .SUB, .MUL, .DIV, .MOD, .UADD, .USUB, .UMUL, .UDIV, .UMOD, .SHR, .SHL, .AND, .OR, .XOR => {
						if (!last){
							if (targets_reg(inst.list.items[1])) |dest| {
								for (live_after.items[0].items) |live| {
									if (!std.mem.eql(u8, live.atom.text, dest.atom.text)){
										after.append(live)
											catch unreachable;
									}
								}
							}
						}
						else{
							last = false;
							for (block.live_out.items)|out| {
								after.append(out)
									catch unreachable;
							}
						}
						if (targets_reg(inst.list.items[2])) |src| {
							after.append(src)
								catch unreachable;
						}
						if (targets_reg(inst.list.items[3])) |src| {
							after.append(src)
								catch unreachable;
						}
					},
					.CMP => {
						if (!last){
							for (live_after.items[0].items) |live| {
								after.append(live)
									catch unreachable;
							}
						}
						else{
							last = false;
							for (block.live_out.items)|out| {
								after.append(out)
									catch unreachable;
							}
						}
						if (targets_reg(inst.list.items[1])) |src| {
							after.append(src)
								catch unreachable;
						}
						if (targets_reg(inst.list.items[2])) |src| {
							after.append(src)
								catch unreachable;
						}
					},
					.PSH => {
						if (!last){
							for (live_after.items[0].items) |live| {
								after.append(live)
									catch unreachable;
							}
						}
						else{
							last = false;
							for (block.live_out.items)|out| {
								after.append(out)
									catch unreachable;
							}
						}
						if (targets_reg(inst.list.items[1])) |src| {
							after.append(src)
								catch unreachable;
						}
					},
					.POP, .REIF => {
						if (!last){
							if (targets_reg(inst.list.items[1])) |dest| {
								for (live_after.items[0].items) |live| {
									if (!std.mem.eql(u8, live.atom.text, dest.atom.text)){
										after.append(live)
											catch unreachable;
									}
								}
							}
						}
						else{
							last = false;
							for (block.live_out.items)|out| {
								after.append(out)
									catch unreachable;
							}
						}
					},
					.INT => {
						if (!last){
							for (live_after.items[0].items) |live| {
								after.append(live)
									catch unreachable;
							}
						}
						else{
							last = false;
							for (block.live_out.items)|out| {
								after.append(out)
									catch unreachable;
							}
						}
						for (inst.list.items[1..inst.list.items.len]) |arg| {
							after.append(arg)
								catch unreachable;
						}
					},
					else => {
						if (!last){
							for (live_after.items[0].items) |live| {
								after.append(live)
									catch unreachable;
							}
						}
						else{
							last = false;
							for (block.live_out.items)|out| {
								after.append(out)
									catch unreachable;
							}
						}
					}
				}
				live_after.insert(0, after)
					catch unreachable;
			}
			var reg_of = Map(TOKEN).init(self.mem.*);
			var var_of = std.AutoHashMap(TOKEN, *Expr).init(self.mem.*);
			var free_regs = Buffer(TOKEN).init(self.mem.*);
			free_regs.append(.REG4) catch unreachable;
			free_regs.append(.REG5) catch unreachable;
			free_regs.append(.REG6) catch unreachable;
			free_regs.append(.REG7) catch unreachable;
			free_regs.append(.REG8) catch unreachable;
			free_regs.append(.REG9) catch unreachable;
			free_regs.append(.REG10) catch unreachable;
			for (block.start .. block.end) |index| {
				const after = live_after.items[index-block.start];
				const inst = normalized.items[index];
				switch (inst.list.items[0].atom.tag){
					.REG => {
						const variable = inst.list.items[1].atom.text;
						if (reg_of.get(variable)) |_| { }
						else{
							if (free_regs.items.len == 0){
								self.spill(inst.list.items[1], block, &stack_offsets, &reg_of, &var_of, &stack_position, &new);
							}
							else{
								const reg = free_regs.orderedRemove(0);
								if (var_of.get(reg)) |old_var| {
									_ = reg_of.remove(old_var.atom.text);
									_ = var_of.remove(reg);
								}
								reg_of.put(variable, reg)
									catch unreachable;
								var_of.put(reg, inst.list.items[1])
									catch unreachable;
							}
						}
						i += 1;
					},
					.MOV => {
						self.color_write(inst.list.items[1], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
						self.color_read(inst.list.items[2], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
					},
					.ADD, .SUB, .MUL, .DIV, .MOD, .UADD, .USUB, .UMUL, .UDIV, .UMOD, .SHR, .SHL, .AND, .OR, .XOR => {
						self.color_write(inst.list.items[1], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
						self.color_read(inst.list.items[2], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
						self.color_read(inst.list.items[3], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
					},
					.NOT, .COM => {
						self.color_write(inst.list.items[1], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
						self.color_read(inst.list.items[2], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
					},
					.CMP => {
						self.color_read(inst.list.items[1], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
						self.color_read(inst.list.items[2], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
					},
					.PSH => {
						self.color_read(inst.list.items[1], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
					},
					.POP => {
						self.color_write(inst.list.items[1], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
					},
					.REIF => {
						self.color_write(inst.list.items[1], block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
					},
					.INT => {
						for (inst.list.items[1..inst.list.items.len]) |arg| {
							self.color_read(arg, block, &reg_of, &var_of, &free_regs, &stack_position, &stack_offsets, &new);
						}
					},
					else => {}
				}
				var free_list = Buffer(TOKEN).init(self.mem.*);
				var it = reg_of.iterator();
				outer: while (it.next()) |entry| {
					const candidate = entry.key_ptr.*;
					for (after.items) |live| {
						if (std.mem.eql(u8, live.atom.text, candidate)){
							continue :outer;
						}
					}
					if (used_in_inst(inst, candidate)) {
						continue;
					}
					free_list.append(entry.value_ptr.*)
						catch unreachable;
				}
				for (free_list.items) |register| {
					if (var_of.get(register)) |candidate| {
						if (stack_offsets.get(candidate.atom.text)) |inner_offset| {
							self.store_to_stack_offset(register, inner_offset, &new);
						}
						else{
							stack_offsets.put(candidate.atom.text, stack_position)
								catch unreachable;
							self.push_to_stack_offset(register, &new);
							stack_position += 8;
						}
						free_regs.append(register)
							catch unreachable;
						_ = var_of.remove(register);
						_ = reg_of.remove(candidate.atom.text);
					}
					else{
						std.debug.assert(false);
					}
				}
				const clone = deep_copy(self.mem, inst);
				self.color_expr(clone, &reg_of);
				new.append(clone)
					catch unreachable;
				var post_free_list = Buffer(TOKEN).init(self.mem.*);
				var it2 = reg_of.iterator();
				outer_post: while (it2.next()) |entry| {
					const candidate = entry.key_ptr.*;
					for (after.items) |live| {
						if (std.mem.eql(u8, live.atom.text, candidate)){
							continue :outer_post;
						}
					}
					post_free_list.append(entry.value_ptr.*)
						catch unreachable;
				}
				for (post_free_list.items) |reg| {
					if (var_of.get(reg)) |candidate| {
						if (stack_offsets.get(candidate.atom.text)) |offset| {
							self.store_to_stack_offset(reg, offset, &new);
						}
						else {
							stack_offsets.put(candidate.atom.text, stack_position)
								catch unreachable;
							self.push_to_stack_offset(reg, &new);
							stack_position += 8;
						}
						free_regs.append(reg)
							catch unreachable;
						_ = var_of.remove(reg);
						_ = reg_of.remove(candidate.atom.text);
					}
					else {
						std.debug.assert(false);
					}
				}
			}
			for (block.live_out.items) |out| {
				if (reg_of.get(out.atom.text)) |reg| {
					if (stack_offsets.get(out.atom.text)) |offset| {
						self.store_to_stack_offset(reg, offset, &new);
					}
					else{
						stack_offsets.put(out.atom.text, stack_position)
							catch unreachable;
						self.push_to_stack_offset(reg, &new);
						stack_position += 8;
					}
				}
			}
		}
		return new;
	}

	pub fn color_expr(self: *Program, expr: *Expr, reg_of: *Map(TOKEN)) void {
		switch (expr.*){
			.atom => {
				switch(expr.atom.tag){
					.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
						return;
					},
					else => {}
				}
				if (std.mem.eql(u8, "fp", expr.atom.text)){
					expr.atom.tag = .FPTR;
					return;
				}
				if (std.mem.eql(u8, "sp", expr.atom.text)){
					expr.atom.tag = .SPTR;
					return;
				}
				if (reg_of.get(expr.atom.text)) |reg| {
					expr.atom.tag = reg;
					return;
				}
				std.debug.print("No register allocated for {s}\n", .{expr.atom.text});
				std.debug.assert(false);
			},
			.list => {
				switch (expr.list.items[0].atom.tag){
					.LABEL, .JMP, .JEQ, .JNE, .JGE, .JGT, .JLE, .JLT => {
						return;
					},
					else => {}
				}
				var first = true;
				for (expr.list.items) |sub| {
					if (first){
						first = false;
						continue;
					}
					self.color_expr(sub, reg_of);
				}
			}
		}
	}

	pub fn color_read(self: *Program, expr: *Expr, block: *BBlock, reg_of: *Map(TOKEN), var_of: *std.AutoHashMap(TOKEN, *Expr), free_regs: *Buffer(TOKEN), stack_position: *u64, stack_offsets: *Map(u64), new: *Buffer(*Expr)) void {
		var variable = expr;
		if (expr.* == .list){
			variable = expr.list.items[1];
		}
		switch (variable.atom.tag){
			.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
				return;
			},
			else => {}
		}
		std.debug.print("checking read to variable {s}\n", .{variable.atom.text});
		if (reg_of.get(variable.atom.text)) |_| {
			std.debug.print("  already allocated\n", .{});
			return;
		}
		if (stack_offsets.get(variable.atom.text)) |offset| {
			std.debug.print("  exists at an offset\n", .{});
			if (free_regs.items.len == 0){
				std.debug.print("    no free registers, spilling\n", .{});
				self.spill(variable, block, stack_offsets, reg_of, var_of, stack_position, new);
			}
			else{
				const reg = free_regs.orderedRemove(0);
				std.debug.print("    allocating free register {}\n", .{reg});
				if (var_of.get(reg)) |old_var| {
					std.debug.print("    purging old relation {s} -> {}\n", .{old_var.atom.text, reg});
					_ = reg_of.remove(old_var.atom.text);
					_ = var_of.remove(reg);
				}
				reg_of.put(variable.atom.text, reg)
					catch unreachable;
				var_of.put(reg, variable)
					catch unreachable;
				self.load_from_stack_offset(reg, offset, new);
			}
		}
		else if (free_regs.items.len == 0){
			std.debug.print("  no free registers, spilling\n", .{});
			self.spill(variable, block, stack_offsets, reg_of, var_of, stack_position, new);
		}
		else{
			const reg = free_regs.orderedRemove(0);
			std.debug.print("  allocating free register {}\n", .{reg});
			if (var_of.get(reg)) |old_var| {
				std.debug.print("  purging old relation {s} -> {}\n", .{old_var.atom.text, reg});
				_ = reg_of.remove(old_var.atom.text);
				_ = var_of.remove(reg);
			}
			reg_of.put(variable.atom.text, reg)
				catch unreachable;
			var_of.put(reg, variable)
				catch unreachable;
		}
	}

	pub fn color_write(self: *Program, expr: *Expr, block: *BBlock, reg_of: *Map(TOKEN), var_of: *std.AutoHashMap(TOKEN, *Expr), free_regs: *Buffer(TOKEN), stack_position: *u64, stack_offsets: *Map(u64), new: *Buffer(*Expr)) void {
		var variable = expr;
		if (expr.* == .list){
			variable = expr.list.items[1];
		}
		switch (variable.atom.tag){
			.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
				return;
			},
			else => {}
		}
		std.debug.print("checking write to variable {s}\n", .{variable.atom.text});
		if (reg_of.get(variable.atom.text)) |_| {
			std.debug.print("  already allocated\n", .{});
			return;
		}
		if (stack_offsets.get(variable.atom.text)) |_| {
			std.debug.print("  exists at an offset\n", .{});
			if (free_regs.items.len == 0){
				std.debug.print("    no free registers, spilling\n", .{});
				self.spill(variable, block, stack_offsets, reg_of, var_of, stack_position, new);
			}
			else{
				const reg = free_regs.orderedRemove(0);
				std.debug.print("    allocating free register {}\n", .{reg});
				if (var_of.get(reg)) |old_var| {
					std.debug.print("    purging old relation {s} -> {}\n", .{old_var.atom.text, reg});
					_ = reg_of.remove(old_var.atom.text);
					_ = var_of.remove(reg);
				}
				reg_of.put(variable.atom.text, reg)
					catch unreachable;
				var_of.put(reg, variable)
					catch unreachable;
			}
		}
		else if (free_regs.items.len == 0){
			std.debug.print("  no free registers, spilling\n", .{});
			self.spill(variable, block, stack_offsets, reg_of, var_of, stack_position, new);
		}
		else{
			const reg = free_regs.orderedRemove(0);
			std.debug.print("  allocating free register {}\n", .{reg});
			if (var_of.get(reg)) |old_var| {
				std.debug.print("  purging old relation {s} -> {}\n", .{old_var.atom.text, reg});
				_ = reg_of.remove(old_var.atom.text);
				_ = var_of.remove(reg);
			}
			reg_of.put(variable.atom.text, reg)
				catch unreachable;
			var_of.put(reg, variable)
				catch unreachable;
		}
	}

	pub fn spill(
		self: *Program,
		in: *Expr,
		block: *BBlock,
		stack_offsets: *Map(u64),
		reg_of: *Map(TOKEN),
		var_of: *std.AutoHashMap(TOKEN, *Expr),
		stack_position: *u64,
		new: *Buffer(*Expr)
	) void {
		var reg: TOKEN = undefined;
		var it = var_of.iterator();
		var first = true;
		outer: while (it.next()) |entry| {
			const candidate = entry.key_ptr.*;
			if (first){
				first = false;
				reg = candidate;
			}
			const variable = entry.value_ptr.*;
			for (block.live_out.items) |out| {
				if (std.mem.eql(u8, out.atom.text, variable.atom.text)){
					continue :outer;
				}
			}
			reg = candidate;
			break;
		}
		if (var_of.get(reg)) |variable| {
			if (stack_offsets.get(variable.atom.text)) |inner_offset| {
				self.store_to_stack_offset(reg, inner_offset, new);
			}
			else{
				stack_offsets.put(variable.atom.text, stack_position.*)
					catch unreachable;
				self.push_to_stack_offset(reg, new);
				stack_position.* += 8;
			}
		}
		else{
			std.debug.assert(false);
		}
		if (var_of.get(reg)) |old_var| {
			_ = reg_of.remove(old_var.atom.text);
			_ = var_of.remove(reg);
		}
		reg_of.put(in.atom.text, reg)
			catch unreachable;
		var_of.put(reg, in)
			catch unreachable;
	}

	pub fn push_to_stack_offset(self: *Program, reg: TOKEN, new: *Buffer(*Expr)) void {
		var psh = self.mem.create(Expr)
			catch unreachable;
		psh.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		const op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "psh") catch unreachable,
				.pos = 0,
				.tag = .PSH
			}
		};
		const dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
				.pos = 0,
				.tag = reg
			}
		};
		psh.list.append(op) catch unreachable;
		psh.list.append(dest) catch unreachable;
		new.append(psh) catch unreachable;
	}

	pub fn store_to_stack_offset(self: *Program, reg: TOKEN, offset: u64, new: *Buffer(*Expr)) void {
		var load = self.mem.create(Expr)
			catch unreachable;
		load.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		var op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "mov") catch unreachable,
				.pos = 0,
				.tag = .MOV
			}
		};
		var dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "r11") catch unreachable,
				.pos = 0,
				.tag = .REG11
			}
		};
		var src = self.mem.create(Expr)
			catch unreachable;
		src.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "fp") catch unreachable,
				.pos = 0,
				.tag = .FPTR
			}
		};
		load.list.append(op)
			catch unreachable;
		load.list.append(dest)
			catch unreachable;
		load.list.append(src)
			catch unreachable;
		var off = self.mem.create(Expr)
			catch unreachable;
		off.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "sub") catch unreachable,
				.pos = 0,
				.tag = .SUB
			}
		};
		dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "r11") catch unreachable,
				.pos = 0,
				.tag = .REG11
			}
		};
		src = self.mem.create(Expr)
			catch unreachable;
		const buffer = self.mem.alloc(u8, 20)
			catch unreachable;
		const slice = std.fmt.bufPrint(buffer, "{x}", .{offset})
			catch unreachable;
		src.* = Expr{
			.atom = Token{
				.text = slice,
				.pos = 0,
				.tag = .NUM
			}
		};
		off.list.append(op)
			catch unreachable;
		off.list.append(dest)
			catch unreachable;
		off.list.append(dest)
			catch unreachable;
		off.list.append(src)
			catch unreachable;
		var loc = self.mem.create(Expr)
			catch unreachable;
		loc.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "mov") catch unreachable,
				.pos = 0,
				.tag = .MOV
			}
		};
		dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
				.pos = 0,
				.tag = reg
			}
		};
		src = self.mem.create(Expr)
			catch unreachable;
		src.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		const at = self.mem.create(Expr)
			catch unreachable;
		at.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "at") catch unreachable,
				.pos = 0,
				.tag = .AT
			}
		};
		const dref = self.mem.create(Expr)
			catch unreachable;
		dref.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "r11") catch unreachable,
				.pos = 0,
				.tag = .REG11
			}
		};
		src.list.append(at)
			catch unreachable;
		src.list.append(dref)
			catch unreachable;
		loc.list.append(op)
			catch unreachable;
		loc.list.append(src)
			catch unreachable;
		loc.list.append(dest)
			catch unreachable;
		new.append(load) catch unreachable;
		new.append(off) catch unreachable;
		new.append(loc) catch unreachable;

	}

	pub fn load_from_stack_offset(self: *Program, reg: TOKEN, offset: u64, new: *Buffer(*Expr)) void {
		var load = self.mem.create(Expr)
			catch unreachable;
		load.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		var op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "mov") catch unreachable,
				.pos = 0,
				.tag = .MOV
			}
		};
		var dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "r11") catch unreachable,
				.pos = 0,
				.tag = .REG11
			}
		};
		var src = self.mem.create(Expr)
			catch unreachable;
		src.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "fp") catch unreachable,
				.pos = 0,
				.tag = .FPTR
			}
		};
		load.list.append(op)
			catch unreachable;
		load.list.append(dest)
			catch unreachable;
		load.list.append(src)
			catch unreachable;
		var off = self.mem.create(Expr)
			catch unreachable;
		off.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "sub") catch unreachable,
				.pos = 0,
				.tag = .SUB
			}
		};
		dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "r11") catch unreachable,
				.pos = 0,
				.tag = .REG11
			}
		};
		src = self.mem.create(Expr)
			catch unreachable;
		const buffer = self.mem.alloc(u8, 20)
			catch unreachable;
		const slice = std.fmt.bufPrint(buffer, "{x}", .{offset})
			catch unreachable;
		src.* = Expr{
			.atom = Token{
				.text = slice,
				.pos = 0,
				.tag = .NUM
			}
		};
		off.list.append(op)
			catch unreachable;
		off.list.append(dest)
			catch unreachable;
		off.list.append(dest)
			catch unreachable;
		off.list.append(src)
			catch unreachable;
		var loc = self.mem.create(Expr)
			catch unreachable;
		loc.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		op = self.mem.create(Expr)
			catch unreachable;
		op.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "mov") catch unreachable,
				.pos = 0,
				.tag = .MOV
			}
		};
		dest = self.mem.create(Expr)
			catch unreachable;
		dest.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "REGISTER") catch unreachable,
				.pos = 0,
				.tag = reg
			}
		};
		src = self.mem.create(Expr)
			catch unreachable;
		src.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		const at = self.mem.create(Expr)
			catch unreachable;
		at.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "at") catch unreachable,
				.pos = 0,
				.tag = .AT
			}
		};
		const dref = self.mem.create(Expr)
			catch unreachable;
		dref.* = Expr{
			.atom = Token{
				.text = self.mem.dupe(u8, "r11") catch unreachable,
				.pos = 0,
				.tag = .REG11
			}
		};
		src.list.append(at)
			catch unreachable;
		src.list.append(dref)
			catch unreachable;
		loc.list.append(op)
			catch unreachable;
		loc.list.append(dest)
			catch unreachable;
		loc.list.append(src)
			catch unreachable;
		new.append(load) catch unreachable;
		new.append(off) catch unreachable;
		new.append(loc) catch unreachable;
	}

	pub fn backward_dfs_cfg(self: *Program, current_block: *BBlock, visited: *std.AutoHashMap(*BBlock, bool)) bool {
		if (visited.get(current_block)) |_| {
			return false;
		}
		var changes = false;
		visited.put(current_block, true)
			catch unreachable;
		for (current_block.next.items) |next| {
			outer: for (next.live_in.items) |in| {
				for (current_block.live_out.items) |out| {
					if (std.mem.eql(u8, in.atom.text, out.atom.text)){
						continue :outer;
					}
				}
				current_block.live_out.append(in)
					catch unreachable;
				changes = true;
			}
		}
		if (changes){
			current_block.live_in.clearRetainingCapacity();
			current_block.live_in.appendSlice(current_block.read_write.items)
				catch unreachable;
			outer: for (current_block.live_out.items) |out| {
				for (current_block.write.items) |def| {
					if (std.mem.eql(u8, out.atom.text, def.atom.text)){
						continue :outer;
					}
				}
				current_block.live_in.append(out)
					catch unreachable;
			}
		}
		for (current_block.prev.items) |prev| {
			changes = changes or self.backward_dfs_cfg(prev, visited);
		}
		return changes;
	}

	pub fn check_var_read(_: *Program, current_block: *BBlock, expr: *Expr) void {
		if (expr.* == .list){
			std.debug.assert(expr.list.items[0].* == .atom);
			std.debug.assert(expr.list.items[0].atom.tag == .AT);
			switch(expr.list.items[1].atom.tag){
				.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
					return;
				},
				else => {}
			}
			for (current_block.write.items) |candidate| {
				if (std.mem.eql(u8, candidate.atom.text, expr.list.items[1].atom.text)){
					return;
				}
			}
			for (current_block.read_write.items) |exists| {
				if (std.mem.eql(u8, exists.atom.text, expr.list.items[1].atom.text)){
					return;
				}
			}
			current_block.read_write.append(expr.list.items[1])
				catch unreachable;
			return;
		}
		switch(expr.atom.tag){
			.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
				return;
			},
			else => {}
		}
		for (current_block.write.items) |candidate| {
			if (std.mem.eql(u8, candidate.atom.text, expr.atom.text)){
				return;
			}
		}
		for (current_block.read_write.items) |exists| {
			if (std.mem.eql(u8, exists.atom.text, expr.atom.text)){
				return;
			}
		}
		current_block.read_write.append(expr)
			catch unreachable;
	}

	pub fn check_var_write(_: *Program, current_block: *BBlock, expr: *Expr) void {
		if (expr.* == .list){
			std.debug.assert(expr.list.items[0].* == .atom);
			std.debug.assert(expr.list.items[0].atom.tag == .AT);
			switch(expr.list.items[1].atom.tag){
				.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
					return;
				},
				else => {}
			}
			for (current_block.write.items) |exists| {
				if (std.mem.eql(u8, exists.atom.text, expr.list.items[1].atom.text)){
					return;
				}
			}
			current_block.write.append(expr.list.items[1])
				catch unreachable;
			return;
		}
		switch(expr.atom.tag){
			.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
				return;
			},
			else => {}
		}
		for (current_block.write.items) |exists| {
			if (std.mem.eql(u8, exists.atom.text, expr.atom.text)){
				return;
			}
		}
		current_block.write.append(expr)
			catch unreachable;
	}

	pub fn evaluate(self: *Program, vm_target: Token, repr: ReifableRepr) *Expr {
		if (debug){
			std.debug.print("Evaluating\n", .{});
		}
		var vm = self.vm.get(vm_target.text);
		if (vm == null){
			vm = self.mem.create(ir.VM)
				catch unreachable;
			vm.?.* = ir.VM.init(self.config);
			self.vm.put(vm_target.text, vm.?)
				catch unreachable;
		}
		var error_buffer = Buffer(ir.Error).init(self.mem.*);
		const bytecode = ir.assemble_bytecode(self.mem, repr.parsed.items, &error_buffer) catch unreachable;
		if (debug){
			for (bytecode, 0..) |byte, i| {
				std.debug.print("{x:02} ", .{byte});
				if (i % 4 == 3){
					std.debug.print("\n", .{});
				}
			}
		}
		var offset:u64 = 0;
		for (repr.reif.static.items) |reif_byte_segment| {
			const reif_bytes = self.mem.alloc(u8, reif_byte_segment.len*8)
				catch unreachable;
			var i: u64 = 0;
			for (reif_byte_segment) |b| {
				reif_bytes[i] = @as(u8, @truncate(b));
				reif_bytes[i+1] = @as(u8, @truncate(b >> 0x8));
				reif_bytes[i+2] = @as(u8, @truncate(b >> 0x10));
				reif_bytes[i+3] = @as(u8, @truncate(b >> 0x18));
				reif_bytes[i+4] = @as(u8, @truncate(b >> 0x20));
				reif_bytes[i+5] = @as(u8, @truncate(b >> 0x28));
				reif_bytes[i+6] = @as(u8, @truncate(b >> 0x30));
				reif_bytes[i+7] = @as(u8, @truncate(b >> 0x38));
				i += 8;
			}
			vm.?.load_bytes(offset, reif_bytes);
			offset += reif_bytes.len;
		}
		self.global_reif.reset_ephemeral_static_region();
		const start = 0x200;
		vm.?.load_bytes(start, bytecode);
		var context = ir.Context.init(self.config, vm.?);
		vm.?.context = &context;
		_ = context.awaken_core(start >> 2) catch {
			std.debug.print("Corrupted vm state\n", .{});
			context.deinit();
		};
		context.await_cores();
		context.deinit();
		if (std.mem.eql(u8, vm_target.text, "vm")){
			const loc = self.mem.create(Expr)
				catch unreachable;
			loc.* = Expr{
				.atom = Token{
					.pos=0,
					.tag=.NUM,
					.text=self.mem.dupe(u8, "0") catch unreachable
				}
			};
			return loc;
		}
		const return_address = vm.?.cores[0].reg[11];
		return self.lift_reif(vm.?, repr.reif, return_address);
	}

	pub fn lift_reif(self: *Program, vm: *ir.VM, reif: Reif, addr: u64) *Expr {
		const start = addr >> 3;
		const n = vm.memory.words[start];
		var output = self.mem.create(Expr)
			catch unreachable;
		output.* = Expr{
			.list = Buffer(*Expr).init(self.mem.*)
		};
		for (0..n) |i| {
			const elem = vm.memory.words[start+i+1];
			const tag = elem & 0xffffffff00000000;
			switch (@as(ReifTag, @enumFromInt(tag))) {
				.reif_val => {
					const buf = self.mem.alloc(u8, 20)
						catch unreachable;
					const slice = std.fmt.bufPrint(buf, "{x}", .{elem & 0xffffffff})
						catch unreachable;
					const loc = self.mem.create(Expr)
						catch unreachable;
					loc.* = Expr{
						.atom = Token{
							.text = slice,
							.pos = 0,
							.tag = .NUM
						}
					};
					output.list.append(loc)
						catch unreachable;
					continue;
				},
				.reif_ptr => {
					const loc = self.lift_reif(vm, reif, elem & 0xffffffff);
					output.list.append(loc)
						catch unreachable;
					continue;
				},
				.reif_sym => {
					if (reif.reverse.get(elem)) |sym| {
						output.list.append(sym)
							catch unreachable;
						continue;
					}
					unreachable;
				},
				.reif_str => {
					const ptr = (elem & 0xffffffff) >> 3;
					const len = vm.memory.words[ptr];
					var si: u64 = 0;
					const string = self.mem.alloc(u8, 2+len)
						catch unreachable;
					string[si] = '"';
					si += 1;
					while (si < (len+1)) {
						string[si] = @truncate(vm.memory.words[ptr + si]);
						si += 1;
					}
					string[si] = '"';
					const sym = self.mem.create(Expr)
						catch unreachable;
					sym.* = Expr{
						.atom = Token{
							.text = string,
							.pos = 0,
							.tag = .STR
						}
					};
					output.list.append(sym)
						catch unreachable;
					continue;
				}
			}
		}
		return output;
	}

	pub fn descend(self: *Program, expr: *Expr, vm_target:Token, err: *Buffer(Error)) ParseError!*Expr {
		switch (expr.*){
			.atom => {
				return expr;
			},
			.list => {
				if (expr.list.items.len == 0){
					return expr;
				}
				while (expr.list.items[0].* != .atom){
					if (expr.list.items[0].list.items.len != 0){
						if (expr.list.items[0].list.items[0].* == .atom){
							if (expr.list.items[0].list.items[0].atom.tag == .FLAT){
								if (expr.list.items[0].list.items.len != 2){
									err.append(set_error(self.mem, expr.list.items[0].list.items[0].atom.pos, "Expected 2 arguments for flatten, found {s}\n", .{expr.list.items[0].list.items[0].atom.text}))
										catch unreachable;
									return ParseError.UnexpectedToken;
								}
								const val = try self.descend(expr.list.items[0].list.items[1], vm_target, err);
								if (val.* == .atom){
									expr.list.items[0] = val;
									break;
								}
								var flathead = Expr{
									.list = Buffer(*Expr).init(self.mem.*)
								};
								flathead.list.appendSlice(val.list.items)
									catch unreachable;
								flathead.list.appendSlice(expr.list.items[1..])
									catch unreachable;
								const loc = self.mem.create(Expr)
									catch unreachable;
								loc.* = flathead;
								return try self.descend(loc, vm_target, err);
							}
						}
					}
					expr.list.items[0] = try self.descend(expr.list.items[0], vm_target, err);
					break;
				}
				if (expr.list.items[0].* == .atom){
					if (expr.list.items[0].atom.tag == .FLAT){
						if (expr.list.items.len != 2){
							err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected 2 arguments for flatten, found {}\n", .{expr.list.items.len}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						expr.list.items[1] = try self.descend(expr.list.items[1], vm_target, err);
						if (expr.list.items[1].* == .list){
							if (expr.list.items[1].list.items.len != 1){
								err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected 1 arguments for flatten list, found {}\n", .{expr.list.items[1].list.items.len}))
									catch unreachable;
								return ParseError.UnexpectedToken;
							}
						}
						return try self.descend(expr.list.items[1].list.items[0], vm_target, err);
					}
					if (expr.list.items[0].atom.tag == .BIND){
						return expr;
					}
					if (expr.list.items[0].atom.tag == .COMP){
						if (expr.list.items.len != 3){
							err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected 3 argumentns for comp block\n", .{}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						if (expr.list.items[2].* == .atom){
							return expr.list.items[1];
						}
						if (expr.list.items[1].* == .list){
							err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected symbol for comp vm target\n", .{}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						if (debug){
							std.debug.print("computing for comp in vm {s}\n", .{expr.list.items[1].atom.text});
						}
						return try self.compute(expr.list.items[2].list, expr.list.items[1].atom, err, true);
					}
					if (expr.list.items[0].atom.tag == .UID){
						if (expr.list.items.len != 3){
							err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected 2 arguments for uid block, found {}\n", .{expr.list.items.len}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						if (expr.list.items[1].* != .list){
							err.append(set_error(self.mem, expr.list.items[1].atom.pos, "Expected list of aliases for uid block, found atom {s}\n", .{expr.list.items[1].atom.text}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						if (expr.list.items[2].* != .list){
							err.append(set_error(self.mem, expr.list.items[2].atom.pos, "Expected list for aliasing, found atom {s}\n", .{expr.list.items[2].atom.text}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						var aliasmap = Map(*Expr).init(self.mem.*);
						for (expr.list.items[1].list.items) |alias| {
							if (alias.* != .atom){
								err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected alias atom, found list\n", .{}))
									catch unreachable;
								return ParseError.UnexpectedToken;
							}
							const loc = self.mem.create(Expr)
								catch unreachable;
							loc.* = Expr{
								.atom = Token {
									.pos = alias.atom.pos,
									.text = uid(self.mem),
									.tag = .IDEN
								}
							};
							aliasmap.put(alias.atom.text, loc)
								catch unreachable;
						}
						const replace = distribute_args(self.mem, aliasmap, expr.list.items[2]);
						return try self.descend(replace, vm_target, err);
					}
					if (expr.list.items[0].atom.tag == .USE){
						if (expr.list.items.len != 2){
							err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected name of file for module code import, found {} arguments instead\n", .{expr.list.items.len}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						const filename = expr.list.items[1];
						if (filename.* != .atom){
							err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected name of file for module, found list instead\n", .{}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						if (filename.atom.tag != .STR){
							err.append(set_error(self.mem, filename.atom.pos, "Expected name of file for module, found {s} instead\n", .{filename.atom.text}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						const extracted = filename.atom.text[1..filename.atom.text.len-1];
						const contents = get_contents(self.mem, extracted) catch {
							err.append(set_error(self.mem, filename.atom.pos, "Couldnt open file {s}\n", .{filename.atom.text}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						};
						const tokens = tokenize(self.mem, contents, err);
						if (err.items.len != 0){
							return ParseError.UnexpectedToken;
						}
						const raw_expressions = try parse_program(self.mem, tokens.items, err);
						const loc = self.mem.create(Expr)
							catch unreachable;
						loc.* = Expr{
							.list = raw_expressions
						};
						return loc;
					}
				}
				var i: u64 = 1;
				while (i < expr.list.items.len){
					if (expr.list.items[i].* == .list){
						if (expr.list.items[i].list.items.len != 0){
							if (expr.list.items[i].list.items[0].* == .atom){
								if (expr.list.items[i].list.items[0].atom.tag == .FLAT){
									if (expr.list.items[i].list.items.len != 2){
										err.append(set_error(self.mem, expr.list.items[i].list.items[0].atom.pos, "Expected 2 arguments for flatten, found {s}\n", .{expr.list.items[i].list.items[0].atom.text}))
											catch unreachable;
										return ParseError.UnexpectedToken;
									}
									const val = try self.descend(expr.list.items[i].list.items[1], vm_target, err);
									if (val.* == .atom){
										expr.list.items[i] = val;
										continue;
									}
									_ = expr.list.orderedRemove(i);
									expr.list.insertSlice(i, val.list.items)
										catch unreachable;
									continue;
								}
							}
						}
					}
					expr.list.items[i] = try self.descend(expr.list.items[i], vm_target, err);
					i += 1;
				}
				if (expr.list.items[0].* == .list){
					return expr;
				}
				if (self.binds.get(expr.list.items[0].atom.text)) |bind| {
					switch (bind.expr.*){
						.atom => {
							if (bind.args.* == .atom){
								return bind.expr;
							}
							if (bind.args.list.items.len == 0){
								return bind.expr;
							}
							const wrapper = self.mem.create(Expr)
								catch unreachable;
							wrapper.* = Expr{
								.list = Buffer(*Expr).init(self.mem.*)
							};
							wrapper.list.append(bind.expr)
								catch unreachable;
							if (wrapper.list.items.len-1 != bind.args.list.items.len-1){
								return wrapper;
							}
							const updated = try apply_args(self.mem, wrapper, bind, err);
							return try self.compute(updated.list, vm_target, err, true);
						},
						.list => {
							if (bind.expr.list.items.len == 0){
								return bind.expr;
							}
							if (expr.list.items.len-1 != bind.args.list.items.len){
								return expr;
							}
							const replace = try apply_args(self.mem, expr, bind, err);
							return try self.descend(replace, vm_target, err);
						}
					}
				}
			}
		}
		return expr;
	}
};

pub fn used_in_inst(inst: *Expr, candidate: []const u8) bool {
	switch (inst.*){
		.atom => {
			if (std.mem.eql(u8, candidate, inst.atom.text)){
				return true;
			}
			return false;
		},
		.list => {
			for (inst.list.items) |sub| {
				if (used_in_inst(sub, candidate)){
					return true;
				}
			}
			return false;
		}
	}
	unreachable;
}

pub fn targets_reg(expr: *Expr) ?*Expr {
	if (expr.* == .list){
		switch(expr.list.items[1].atom.tag){
			.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
				return null;
			},
			else => {}
		}
		return expr.list.items[1];
	}
	switch(expr.atom.tag){
		.NUM, .STR, .REG0, .REG1, .REG2, .REG3, .FPTR, .SPTR => {
			return null;
		},
		else => {}
	}
	return expr;
}

pub fn deep_copy(mem: *const std.mem.Allocator, expr: *Expr) *Expr {
	switch (expr.*) {
		.atom => {
			const clone = mem.create(Expr)
				catch unreachable;
			clone.* = Expr{
				.atom = Token{
					.pos = 0,
					.tag = expr.atom.tag,
					.text = expr.atom.text
				}
			};
			return clone;
		},
		.list => {
			
			const clone = mem.create(Expr)
				catch unreachable;
			clone.* = Expr{
				.list = Buffer(*Expr).init(mem.*)
			};
			for (expr.list.items) |sub| {
				clone.list.append(deep_copy(mem, sub))
					catch unreachable;
			}
			return clone;
		}
	}
	unreachable;
}

const BBlock = struct {
	start: u64,
	end: u64,
	next: Buffer(*BBlock),
	prev: Buffer(*BBlock),
	read_write: Buffer(*Expr),
	write: Buffer(*Expr),
	live_in: Buffer(*Expr),
	live_out: Buffer(*Expr),

	pub fn init(mem: *const std.mem.Allocator, i: u64) *BBlock {
		const loc = mem.create(BBlock)
			catch unreachable;
		loc.* = BBlock{
			.start = i,
			.end = i,
			.next =Buffer(*BBlock).init(mem.*),
			.prev =Buffer(*BBlock).init(mem.*),
			.read_write = Buffer(*Expr).init(mem.*),
			.write = Buffer(*Expr).init(mem.*),
			.live_in = Buffer(*Expr).init(mem.*),
			.live_out = Buffer(*Expr).init(mem.*)
		};
		return loc;
	}
};

const ReifableRepr = struct {
	parsed: Buffer(ir.Instruction),
	reif: Reif
};

pub fn translate_tag(tag: TOKEN) ir.TOKEN {
	switch (tag){
		.MOV => { return ir.TOKEN.MOV;},
		.ADD => { return ir.TOKEN.ADD;},
		.SUB => { return ir.TOKEN.SUB;},
		.MUL => { return ir.TOKEN.MUL;},
		.DIV => { return ir.TOKEN.DIV;},
		.MOD => { return ir.TOKEN.MOD;},
		.UADD => { return ir.TOKEN.UADD;},
		.USUB => { return ir.TOKEN.USUB;},
		.UMUL => { return ir.TOKEN.UMUL;},
		.UDIV => { return ir.TOKEN.UDIV;},
		.UMOD => { return ir.TOKEN.UMOD;},
		.SHR => { return ir.TOKEN.SHR;},
		.SHL => { return ir.TOKEN.SHL;},
		.AND => { return ir.TOKEN.AND;},
		.OR => { return ir.TOKEN.OR;},
		.XOR => { return ir.TOKEN.XOR;},
		.NOT => { return ir.TOKEN.NOT;},
		.COM => { return ir.TOKEN.COM;},
		.CMP => { return ir.TOKEN.CMP;},
		.JMP => { return ir.TOKEN.JMP;},
		.JEQ => { return ir.TOKEN.JEQ;},
		.JNE => { return ir.TOKEN.JNE;},
		.JGT => { return ir.TOKEN.JGT;},
		.JGE => { return ir.TOKEN.JGE;},
		.JLT => { return ir.TOKEN.JLT;},
		.JLE => { return ir.TOKEN.JLE;},
		.CALL => { return ir.TOKEN.CALL;},
		.RET => { return ir.TOKEN.RET;},
		.PSH => { return ir.TOKEN.PSH;},
		.POP => { return ir.TOKEN.POP;},
		.INT => { return ir.TOKEN.INT;},
		else => {
			unreachable;
		}
	}
	unreachable;
}

pub fn is_register(expr: *Expr) ?ir.Register {
	if (expr.* == .list){
		return null;
	}
	if (expr.atom.tag == .REG0) return ir.Register.R0;
	if (expr.atom.tag == .REG1) return ir.Register.R1;
	if (expr.atom.tag == .REG2) return ir.Register.R2;
	if (expr.atom.tag == .REG3) return ir.Register.R3;
	if (expr.atom.tag == .REG4) return ir.Register.R4;
	if (expr.atom.tag == .REG5) return ir.Register.R5;
	if (expr.atom.tag == .REG6) return ir.Register.R6;
	if (expr.atom.tag == .REG7) return ir.Register.R7;
	if (expr.atom.tag == .REG8) return ir.Register.R8;
	if (expr.atom.tag == .REG9) return ir.Register.R9;
	if (expr.atom.tag == .REG10) return ir.Register.R10;
	if (expr.atom.tag == .REG11) return ir.Register.R11;
	if (expr.atom.tag == .FPTR) return ir.Register.FP;
	if (expr.atom.tag == .SPTR) return ir.Register.SP;
	return null;
}

pub fn is_dregister(expr: *Expr) ?ir.Register {
	if (expr.* == .atom){
		return null;
	}
	if (expr.list.items[0].* == .atom){
		if (expr.list.items[0].atom.tag == .AT){
			return is_register(expr.list.items[1]);
		}
	}
	return null;
}

pub fn is_literal(expr: *Expr) ?u16 {
	if (expr.* == .list){
		return null;
	}
	if (expr.atom.tag == .NUM){
		return std.fmt.parseInt(u16, expr.atom.text, 16)
			catch unreachable;
	}
	return null;
}

pub fn is_alu_arg(expr: *Expr) ?ir.ALUArg {
	if (is_register(expr)) |x| {
		return ir.ALUArg{
			.register = x
		};
	}
	if (is_literal(expr)) |y| {
		return ir.ALUArg{
			.literal = @truncate(y)
		};
	}
	return null;
}

const LabelChain = union(enum){
	waiting: Buffer(**Expr),
	fulfilled: *Expr
};

const ReifTag = enum(u64) {
	reif_val = 0x0000000000000000,
	reif_ptr = 0x0000000100000000,
	reif_sym = 0x0000000200000000,
	reif_str = 0x0000000300000000
};

const reifVal = 0x0000000000000000;
const reifPtr = 0x0000000100000000;
const reifSym = 0x0000000200000000;
const reifStr = 0x0000000300000000;

const Reif = struct {
	mem: *const std.mem.Allocator,
	reverse: std.AutoHashMap(u64, *Expr),
	forward: Map(u64),
	static: Buffer([]u64),
	current_symbol: u64,

	pub fn init(mem: *const std.mem.Allocator) Reif {
		return Reif {
			.mem = mem,
			.reverse = std.AutoHashMap(u64, *Expr).init(mem.*),
			.forward = Map(u64).init(mem.*),
			.static = Buffer([]u64).init(mem.*),
			.current_symbol = 0
		};
	}

	pub fn add_relation(self: *Reif, expr: *Expr) u64 {
		if (expr.* == .atom){
			if (expr.atom.tag == .STR){
				var buffer = self.mem.alloc(u64, expr.atom.text.len-1)
					catch unreachable;
				var i:u64 = 0;
				buffer[i] = expr.atom.text.len-2;
				i += 1;
				for (expr.atom.text[1..expr.atom.text.len-1]) |char| {
					buffer[i] = char;
					i += 1;
				}
				var ptr:u64 = 0;
				for (self.static.items) |subbuffer| {
					ptr += subbuffer.len;
				}
				self.static.append(buffer)
					catch unreachable;
				return (ptr*8) | reifStr;
			}
			const sym = self.current_symbol | reifSym;
			self.current_symbol += 1;
			self.forward.put(expr.atom.text, sym)
				catch unreachable;
			self.reverse.put(sym, expr)
				catch unreachable;
			return sym;
		}
		var ptr:u64 = 0;
		for (self.static.items) |subbuffer| {
			ptr += subbuffer.len;
		}
		var buffer = self.mem.alloc(u64, expr.list.items.len+1)
			catch unreachable;
		var i:u64 = 0;
		buffer[i] = expr.list.items.len-1;
		i += 1;
		for (expr.list.items) |sub| {
			buffer[i] = self.add_relation(sub);
			i += 1;
		}
		self.static.append(buffer)
			catch unreachable;
		return (ptr*8) | reifPtr;
	}

	pub fn reset_ephemeral_static_region(self: *Reif) void {
		self.static.clearRetainingCapacity();
	}
};

pub fn apply_args(mem: *const std.mem.Allocator, expr: *Expr, bind: Bind, err: *Buffer(Error)) ParseError!*Expr {
	std.debug.assert(expr.* == .list);
	std.debug.assert(expr.list.items[0].* == .atom);
	std.debug.assert(bind.args.* == .list);
	std.debug.assert(expr.list.items.len-1 == bind.args.list.items.len);
	var argmap = Map(*Expr).init(mem.*);
	for (bind.args.list.items, expr.list.items[1..]) |argname, application| {
		if (argname.* == .list){
			err.append(set_error(mem, bind.name.pos, "Expected argument names to be atoms\n", .{}))
				catch unreachable;
			return ParseError.UnexpectedToken;
		}
		argmap.put(argname.atom.text, application)
			catch unreachable;
	}
	return distribute_args(mem, argmap, bind.expr);
}

pub fn distribute_args(mem: *const std.mem.Allocator, argmap: Map(*Expr), expr: *Expr) *Expr {
	switch (expr.*){
		.atom => {
			if (argmap.get(expr.atom.text)) |replacement| {
				return replacement;
			}
			return expr;
		},
		.list => {
			const copy = mem.create(Expr)
				catch unreachable;
			copy.* = Expr{
				.list = Buffer(*Expr).init(mem.*)
			};
			for (0 .. expr.list.items.len) |i| {
				copy.list.append(distribute_args(mem, argmap, expr.list.items[i]))
					catch unreachable;
			}
			return copy;
		}
	}
	unreachable;
}

pub fn expr_to_bind(mem: *const std.mem.Allocator, bind: *Expr, err: *Buffer(Error)) ParseError!Bind {
	if (bind.* == .atom){
		err.append(set_error(mem, bind.atom.pos, "Expected bind, found {s}\n", .{bind.atom.text}))
			catch unreachable;
		return ParseError.UnexpectedToken;
	}
	if (bind.list.items.len != 4){
		err.append(set_error(mem, 0, "Expected 3 arguments for bind special form, found {}\n", .{bind.list.items.len}))
			catch unreachable;
		return ParseError.UnexpectedToken;
	}
	if (bind.list.items[0].* == .list){
		err.append(set_error(mem, bind.atom.pos, "Expected token for bind name, found list\n", .{}))
			catch unreachable;
		return ParseError.UnexpectedToken;
	}
	return Bind{
		.name = bind.list.items[1].atom,
		.args = bind.list.items[2],
		.expr = bind.list.items[3]
	};
}

pub fn uid(mem: *const std.mem.Allocator) []u8 {
	var new = mem.alloc(u8, internal_uid.len)
		catch unreachable;
	var i: u64 = 0;
	var inc: bool = false;
	while (i < new.len){
		if (internal_uid[i] < 'Z'){
			new[i] = internal_uid[i] + 1;
			i += 1;
			break;
		}
		new[i] = 'A';
		inc = true;
		i += 1;
	}
	if (inc){
		new[i] = internal_uid[i]+1;
	}
	while (i < new.len){
		new[i] = internal_uid[i];
		i += 1;
	}
	internal_uid = new;
	return new;
}
