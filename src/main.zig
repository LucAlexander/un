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
	var filename = Buffer(u8).init(mem);
	filename.appendSlice("test.un")
		catch unreachable;
	const contents = try get_contents(&mem, filename.items);
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
	const raw_expressions = parse_program(&mem, tokens.items, &error_log) catch {
		for (error_log.items) |err| {
			show_error(contents, err);
		}
		return;
	};
	for (raw_expressions.items) |expr| {
		show_expr(expr, 1);
	}
	std.debug.print("\n", .{});
	var program = Program.init(&mem);
	const val = program.compute(raw_expressions, &error_log) catch {
		for (error_log.items) |err| {
			show_error(contents, err);
		}
		return;
	};
	show_expr(val, 1);
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
	if (token.tag == .FPTR){
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
	vm: ir.VM,
	
	pub fn init(mem: *const std.mem.Allocator) Program {
		const config = ir.Config{
			.screen_width = 1,
			.screen_height = 1,
			.cores = 4,
			.mem_size = 0x100000,
			.mem = mem.*
		};
		return Program {
			.binds = Map(Bind).init(mem.*),
			.mem=mem,
			.config = config,
			.vm = ir.VM.init(config)
		};
	}

	pub fn compute(self: *Program, program: Buffer(*Expr), err: *Buffer(Error)) ParseError!*Expr {
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
						if (expr.list.items[0].atom.tag == .BIND){
							const bind = try expr_to_bind(self.mem, expr, err);
							self.binds.put(bind.name.text, bind)
								catch unreachable;
							continue;
						}
					}
					const candidate = try self.descend(expr, err);
					if (candidate.* == .list){
						if (candidate.list.items.len == 4){
							if (candidate.list.items[0].atom.tag == .BIND){
								const bind = try expr_to_bind(self.mem, candidate, err);
								self.binds.put(bind.name.text, bind)
									catch unreachable;
								continue;
							}
						}
					}
					if (self.binds.count() != old_binds){
						old_binds = self.binds.count();
						continue;
					}
					if (self.parse_ir(candidate)) |repr| {
						return self.evaluate(repr);
					}
					return candidate;
				}
			}
		}
	}

	pub fn normalize(self: *Program, normalized: *Buffer(*Expr), reif: *Reif, expr: *Expr, full: bool) ?*Expr {
		var limit = expr.list.items.len-1;
		if (full){
			limit += 1;
		}
		for (expr.list.items[0..limit]) |inst| {
			if (inst.* == .atom){
				return null;
			}
			if (inst.list.items[0].* == .list){
				return null;
			}
			switch (inst.list.items[0].atom.tag){
				.REG, .LABEL => {
					if (inst.list.items.len != 2){
						return null;
					}
					if (self.expect_token(normalized, reif, &inst.list.items[1])){
						normalized.append(inst)
							catch unreachable;
						continue;
					}
					return null;
				},
				.MOV => {
					if (inst.list.items.len != 3){
						return null;
					}
					if (self.expect_register(normalized, reif, &inst.list.items[1])){
						if (self.expect_dregister(normalized, reif, inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (self.expect_register(normalized, reif, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (self.expect_token(normalized, reif, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (inst.list.items[2].* == .list){
							const adr = reif.add_relation(inst.list.items[2]);
							const buf = self.mem.alloc(u8, 20)
								catch unreachable;
							const s = std.fmt.bufPrint(buf, "{d}", .{adr})
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
					}
					if (self.expect_dregister(normalized, reif, inst.list.items[1])){
						if (self.expect_dregister(normalized, reif, inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (self.expect_register(normalized, reif, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (self.expect_token(normalized, reif, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (inst.list.items[2].* == .list){
							const adr = reif.add_relation(inst.list.items[2]);
							const buf = self.mem.alloc(u8, 20)
								catch unreachable;
							const s = std.fmt.bufPrint(buf, "{d}", .{adr})
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
					}
					return null;
				},
				.ADD, .SUB, .MUL, .DIV, .MOD, .UADD, .USUB, .UMUL, .UDIV, .UMOD, .SHR, .SHL, .AND, .OR, .XOR => {
					if (inst.list.items.len != 4){
						return null;
					}
					if (self.expect_register(normalized, reif, &inst.list.items[1])){
						if (self.expect_alu_arg(normalized, reif, &inst.list.items[2])){
							if (self.expect_alu_arg(normalized, reif, &inst.list.items[3])){
								normalized.append(inst)
									catch unreachable;
								continue;
							}
						}
					}
					return null;
				},
				.NOT, .COM, .CMP=> {
					if (inst.list.items.len != 2){
						return null;
					}
					if (self.expect_register(normalized, reif, &inst.list.items[1])){
						if (self.expect_alu_arg(normalized, reif, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
					}
					return null;
				},
				.JMP, .JEQ, .JNE, .JGT, .JGE, .JLT, .JLE, .CALL => {
					if (inst.list.items.len != 2){
						return null;
					}
					if (self.expect_token(normalized, reif, &inst.list.items[1])){
						normalized.append(inst)
							catch unreachable;
						continue;
					}
					return null;
				},
				.RET => {
					if (inst.list.items.len != 2){
						return null;
					}
					if (self.expect_alu_arg(normalized, reif, &inst.list.items[1])){
						normalized.append(inst)
							catch unreachable;
						continue;
					}
					return null;
				},
				.PSH, .POP => {
					if (inst.list.items.len != 2){
						return null;
					}
					if (self.expect_register(normalized, reif, &inst.list.items[1])){
						normalized.append(inst)
							catch unreachable;
						continue;
					}
					return null;
				},
				.INT => {
					normalized.append(inst)
						catch unreachable;
					continue;
				},
				else => {
					return null;
				}
			}
		}
		return expr.list.items[expr.list.items.len-1];
	}

	pub fn parse_ir(self: *Program, programexpr: *Expr) ?ReifableRepr {
		if (programexpr.* == .atom){
			return null;
		}
		if (programexpr.list.items.len == 0){
			return null;
		}
		var normalized = Buffer(*Expr).init(self.mem.*);
		var reif = Reif.init(self.mem);
		if (self.normalize(&normalized, &reif, programexpr, true) == null){
			if (debug){
				std.debug.print("Failed normalization parse\n", .{});
			}
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
		self.color(&normalized);
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
					return null;
				}
			}
		}
		return ReifableRepr{
			.parsed = parsed,
			.reif = reif
		};
	}

	pub fn inscribe_labels(self: *Program, normalized: *Buffer(*Expr)) void {
		var i: u64 = 0;
		var chainmap = Map(LabelChain).init(self.mem.*);
		while (i < normalized.items.len){
			const expr = normalized.items[i];
			switch (expr.list.items[0].atom.tag){
				.JMP, .JEQ, .JNE, .JLE, .JGE, .JLT, .JGT, .CALL => {
					if (chainmap.getPtr(expr.list.items[1].atom.text)) |link| {
						if (link.* == .waiting){
							link.waiting.append(&expr.list.items[1])
								catch unreachable;
						}
						else if (link.* == .fulfilled){
							expr.list.items[1] = link.fulfilled;
						}
					}
					else{
						var newchain = LabelChain{
							.waiting = Buffer(**Expr).init(self.mem.*)
						};
						newchain.waiting.append(&expr.list.items[1])
							catch unreachable;
						chainmap.put(expr.list.items[1].atom.text, newchain)
							catch unreachable;
					}
					i += 1;
					continue;
				},
				.LABEL => {
					const buf = self.mem.alloc(u8, 20)
						catch unreachable;
					const slice = std.fmt.bufPrint(buf, "{}", .{i})
						catch unreachable;
					const replacement = self.mem.create(Expr)
						catch unreachable;
					replacement.* = Expr{
						.atom = Token{
							.pos = 0,
							.text = slice,
							.tag = .NUM
						}
					};
					if (chainmap.get(expr.list.items[1].atom.text)) |link| {
						if (link == .waiting){
							for (link.waiting.items) |entry| {
								entry.* = replacement;
							}
						}
					}
					chainmap.put(expr.list.items[1].atom.text, LabelChain{
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
			std.debug.assert(entry.value_ptr.* == .fulfilled);
		}
	}

	pub fn flatten_interrupts(self: *Program, normalized: *Buffer(*Expr)) void {
		var i: u64 = 0;
		while (i < normalized.items.len) : (i += 1) {
			const expr = normalized.items[i];
			std.debug.assert(expr.* == .list);
			std.debug.assert(expr.list.items[0].* == .atom);
			switch(expr.list.items[0].atom.tag){
				.INT => {
					std.debug.assert(expr.list.items.len < 5);
					self.push_register(normalized, i, .REG2);
					i += 1;
					self.push_register(normalized, i, .REG1);
					i += 1;
					self.push_register(normalized, i, .REG0);
					i += 1;
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
					self.pop_register(normalized, &i, .REG0);
					self.pop_register(normalized, &i, .REG1);
					self.pop_register(normalized, &i, .REG2);
					self.push_register(normalized, i+1, .REG3);
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
			  (source.list.items[1].atom.tag != .REG0 and
			  source.list.items[1].atom.tag != .REG1 and
			  source.list.items[1].atom.tag != .REG2)){
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
			text = self.mem.dupe(u8, "16")
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

	pub fn pop_register(self: Program, normalized: *Buffer(*Expr), i: *u64, register: TOKEN) void {
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
		normalized.insert(i.*, push)
			catch unreachable;
		i.* += 1;
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

	pub fn color_register(self: *Program, normalized: *Buffer(*Expr), i: *u64, expr: *Expr, regmap: *Map(ir.Register), q: *Buffer(ir.Register), vacated: *Map(u64)) void {
		if (expr.* != .atom){
			return;
		}
		if (regmap.get(expr.atom.text)) |old| {
			if (vacated.get(expr.atom.text)) |offset| {
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
						.text = self.mem.dupe(u8, "r3") catch unreachable,
						.pos = 0,
						.tag = .REG3
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
				op = self.mem.create(Expr)
					catch unreachable;
				op.* = Expr{
					.atom = Token{
						.text = self.mem.dupe(u8, "sub") catch unreachable,
						.pos = 0,
						.tag = .MOV
					}
				};
				dest = self.mem.create(Expr)
					catch unreachable;
				dest.* = Expr{
					.atom = Token{
						.text = self.mem.dupe(u8, "fp") catch unreachable,
						.pos = 0,
						.tag = .FPTR
					}
				};
				src = self.mem.create(Expr)
					catch unreachable;
				const buffer = self.mem.alloc(u8, 20)
					catch unreachable;
				const slice = std.fmt.bufPrint(buffer, "{}", .{offset})
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
						.text = self.mem.dupe(u8, "r3") catch unreachable,
						.pos = 0,
						.tag = .REG3
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
				normalized.insert(i.*, load)
					catch unreachable;
				normalized.insert(i.*, off)
					catch unreachable;
				normalized.insert(i.*, loc)
					catch unreachable;
				expr.atom.tag = .REG3;
				i.* += 3;
				return;
			}
			for (q.items, 0..) |reg, k| {
				if (old == reg){
					const item = q.orderedRemove(k);
					q.append(item)
						catch unreachable;
					break;
				}
			}
			switch (old){
				ir.Register.R0 => {
					expr.atom.tag = .REG0;
				},
				ir.Register.R1 => {
					expr.atom.tag = .REG1;
				},
				ir.Register.R2 => {
					expr.atom.tag = .REG2;
				},
				else => {
					unreachable;
				}
			}
		}
	}

	pub fn color(self: *Program, normalized: *Buffer(*Expr)) void {
		var regmap = Map(ir.Register).init(self.mem.*);
		var q = Buffer(ir.Register).init(self.mem.*);
		q.append(ir.Register.R0) catch unreachable;
		q.append(ir.Register.R1) catch unreachable;
		q.append(ir.Register.R2) catch unreachable;
		var vacated = Map(u64).init(self.mem.*);
		var stack_position: u64 = 0;
		var i: u64 = 0;
		while (i<normalized.items.len) : (i += 1) {
			const expr = normalized.items[i];
			std.debug.assert(expr.list.items[0].* == .atom);
			switch(expr.list.items[0].atom.tag){
				.REG => {
					const register = q.orderedRemove(0);
					q.append(register)
						catch unreachable;
					if (vacated.get(expr.list.items[1].atom.text)) |_| {
						_ = vacated.remove(expr.list.items[1].atom.text);
					}
					var it = regmap.iterator();
					while (it.next()) |elem| {
						if (elem.value_ptr.* == register){
							vacated.put(elem.key_ptr.*, stack_position)
								catch unreachable;
							var loc = self.mem.create(Expr)
								catch unreachable;
							loc.* = Expr{
								.list = Buffer(*Expr).init(self.mem.*)
							};
							const left = self.mem.create(Expr)
								catch unreachable;
							left.* = Expr{
								.atom = Token{
									.text = self.mem.dupe(u8, "psh") catch unreachable,
									.pos = 0,
									.tag = .PSH
								}
							};
							loc.list.append(left)
								catch unreachable;
							switch (register) {
								ir.Register.R0 => {
									const right = self.mem.create(Expr)
										catch unreachable;
									right.* = Expr{
										.atom = Token{
											.text = expr.list.items[1].atom.text,
											.pos = expr.list.items[1].atom.pos,
											.tag = .REG0
										}
									};
									loc.list.append(right)
										catch unreachable;					
								},
								ir.Register.R1 => {
									const right = self.mem.create(Expr)
										catch unreachable;
									right.* = Expr{
										.atom = Token{
											.text = expr.list.items[1].atom.text,
											.pos = expr.list.items[1].atom.pos,
											.tag = .REG1
										}
									};
									loc.list.append(right)
										catch unreachable;					
								},
								ir.Register.R2 => {
									const right = self.mem.create(Expr)
										catch unreachable;
									right.* = Expr{
										.atom = Token{
											.text = expr.list.items[1].atom.text,
											.pos = expr.list.items[1].atom.pos,
											.tag = .REG2
										}
									};
									loc.list.append(right)
										catch unreachable;					
								},
								else => {
									unreachable;
								}
							}
							normalized.insert(i, loc)
								catch unreachable;
							stack_position += 8;
							i += 1;
							break;
						}
					}
					regmap.put(expr.list.items[1].atom.text, register)
						catch unreachable;
				},
				.LABEL => {
					continue;
				},
				.MOV => {
					self.color_register(normalized, &i, expr.list.items[1], &regmap, &q, &vacated);
					self.color_register(normalized, &i, expr.list.items[2], &regmap, &q, &vacated);
				},
				.ADD, .SUB, .MUL, .DIV, .MOD, .UADD, .USUB, .UMUL, .UDIV, .UMOD, .SHR, .SHL, .AND, .OR, .XOR => {
					self.color_register(normalized, &i, expr.list.items[1], &regmap, &q, &vacated);
					self.color_register(normalized, &i, expr.list.items[2], &regmap, &q, &vacated);
					self.color_register(normalized, &i, expr.list.items[3], &regmap, &q, &vacated);
				},
				.NOT, .COM, .CMP => {
					self.color_register(normalized, &i, expr.list.items[1], &regmap, &q, &vacated);
					self.color_register(normalized, &i, expr.list.items[2], &regmap, &q, &vacated);
				},
				.JMP, .JEQ, .JNE, .JGT, .JGE, .JLT, .JLE, .CALL, => {
					continue;
				},
				.RET => {
					self.color_register(normalized, &i, expr.list.items[1], &regmap, &q, &vacated);
				},
				.PSH => {
					stack_position += 8;
					self.color_register(normalized, &i, expr.list.items[1], &regmap, &q, &vacated);
				},
				.POP => {
					stack_position -= 8;
					self.color_register(normalized, &i, expr.list.items[1], &regmap, &q, &vacated);
				},
				.INT => {
					var k: u64 = 1;
					while (k<expr.list.items.len){
						self.color_register(normalized, &i, expr.list.items[k], &regmap, &q, &vacated);
						k += 1;
					}
				},
				else => {
					unreachable;
				}
			}
		}
	}

	pub fn expect_alu_arg(self: *Program, normalized: *Buffer(*Expr), reif: *Reif, expr: **Expr) bool {
		return (self.expect_register(normalized, reif, expr) or self.expect_token(normalized, reif, expr));
	}

	pub fn expect_register(self: *Program, normalized: *Buffer(*Expr), reif: *Reif, expr: **Expr) bool {
		return self.expect_token(normalized, reif, expr);
	}

	pub fn expect_dregister(self: *Program, normalized: *Buffer(*Expr), reif: *Reif, expr: *Expr) bool {
		if (expr.* == .atom){
			return false;
		}
		if (expr.list.items.len != 2){
			return false;
		}
		if (self.expect_register(normalized, reif, &expr.list.items[1])){
			return true;
		}
		if (self.normalize(normalized, reif, expr.list.items[1], false)) |norm| {
			expr.list.items[1] = norm;
			return self.expect_register(normalized, reif, &expr.list.items[1]);
		}
		return false;
	}

	pub fn expect_token(self: *Program, normalized: *Buffer(*Expr), reif: *Reif, expr: **Expr) bool {
		if (expr.*.* == .list){
			if (self.normalize(normalized, reif, expr.*, false)) |norm| {
				if (norm.* == .list){
					return false;
				}
				expr.* = norm;
				return true;
			}
			return false;
		}
		return true;
	}

	pub fn evaluate(self: *Program, repr: ReifableRepr) *Expr {
		var error_buffer = Buffer(ir.Error).init(self.mem.*);
		const bytecode = ir.assemble_bytecode(self.mem, repr.parsed.items, &error_buffer) catch unreachable;
		var offset:u64 = 0;
		for (repr.reif.static.items) |reif_byte_segment| {
			const reif_bytes = std.mem.bytesAsSlice(u8, reif_byte_segment[0..]);
			self.vm.load_bytes(offset, reif_bytes);
			offset += reif_bytes.len;
		}
		const start = 0x200;
		self.vm.load_bytes(start, bytecode);
		var context = ir.Context.init(self.config, &self.vm);
		self.vm.context = &context;
		_ = context.awaken_core(start >> 2) catch {
			std.debug.print("Corrupted vm state\n", .{});
			context.deinit();
		};
		context.await_cores();
		context.deinit();
		//TODO lift out reifeid list structure
		return self.mem.create(Expr) catch unreachable;//TODO placeholder
	}

	pub fn descend(self: *Program, expr: *Expr, err: *Buffer(Error)) ParseError!*Expr {
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
								const val = try self.descend(expr.list.items[0].list.items[1], err);
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
								return try self.descend(loc, err);
							}
						}
					}
					expr.list.items[0] = try self.descend(expr.list.items[0], err);
					break;
				}
				if (expr.list.items[0].* == .atom){
					if (expr.list.items[0].atom.tag == .FLAT){
						if (expr.list.items.len != 2){
							err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected 2 arguments for flatten, found {}\n", .{expr.list.items.len}))
								catch unreachable;
							return ParseError.UnexpectedToken;
						}
						expr.list.items[1] = try self.descend(expr.list.items[1], err);
						if (expr.list.items[1].* == .list){
							if (expr.list.items[1].list.items.len != 1){
								err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected 1 arguments for flatten list, found {}\n", .{expr.list.items[1].list.items.len}))
									catch unreachable;
								return ParseError.UnexpectedToken;
							}
						}
						return try self.descend(expr.list.items[1].list.items[0], err);
					}
					if (expr.list.items[0].atom.tag == .BIND){
						const bind = try expr_to_bind(self.mem, expr, err);
						if (bind.expr.* == .list){
							if (bind.expr.list.items[0].* == .atom){
								if (bind.expr.list.items[0].atom.tag == .COMP){
									self.binds.put(bind.name.text, bind)
										catch unreachable;
									const nop = self.mem.create(Expr)
										catch unreachable;
									nop.* = Expr{
										.list = Buffer(*Expr).init(self.mem.*)
									};
									return nop;
								}
							}
						}
						expr.list.items[3] = try self.descend(expr.list.items[3], err);
						return expr;
					}
					if (expr.list.items[0].atom.tag == .COMP){
						if (expr.list.items[1].* == .atom){
							return expr.list.items[1];
						}
						return try self.compute(expr.list.items[1].list, err);
					}
					if (expr.list.items[0].atom.tag == .UID){
						if (expr.list.items.len != 3){
							err.append(set_error(self.mem, expr.list.items[0].atom.pos, "Expected 3 arguments for uid block\n", .{}))
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
						const replace = distribute_args(aliasmap, expr.list.items[2]);
						return try self.descend(replace, err);
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
									const val = try self.descend(expr.list.items[i].list.items[1], err);
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
					expr.list.items[i] = try self.descend(expr.list.items[i], err);
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
							return try self.compute(updated.list, err);
						},
						.list => {
							if (bind.expr.list.items.len == 0){
								return bind.expr;
							}
							if (expr.list.items.len-1 != bind.args.list.items.len){
								return expr;
							}
							const replace = try apply_args(self.mem, expr, bind, err);
							return try self.descend(replace, err);
						}
					}
				}
			}
		}
		return expr;
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
			return ir.TOKEN.MOV; //TODO should be an error case somehow
		}
	}
	return ir.TOKEN.MOV; //TODO this too
}

pub fn is_register(expr: *Expr) ?ir.Register {
	if (expr.* == .list){
		return null;
	}
	if (expr.atom.tag == .REG0) return ir.Register.R0;
	if (expr.atom.tag == .REG1) return ir.Register.R1;
	if (expr.atom.tag == .REG2) return ir.Register.R2;
	if (expr.atom.tag == .REG3) return ir.Register.R3;
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

pub fn is_literal(_: *Expr) ?u16 {
	//TODO
	return 0;
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

const reif_val = 0x00000000000000000;
const reif_ptr = 0x00000000100000000;
const reif_sym = 0x00000000200000000;

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
		//TODO numerals are different from symbols
		if (expr.* == .atom){
			const sym = self.current_symbol | reif_sym;
			self.current_symbol += 1;
			self.forward.put(expr.atom.text, sym)
				catch unreachable;
			self.reverse.put(sym, expr)
				catch unreachable;
			return sym;
		}
		const ptr = self.static.items.len;
		var buffer = self.mem.alloc(u64, expr.list.items.len)
			catch unreachable;
		var i:u64 = 0;
		for (expr.list.items) |sub| {
			buffer[i] = self.add_relation(sub);
			i += 1;
		}
		self.static.append(buffer)
			catch unreachable;
		return (ptr*8) | reif_ptr;
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
	return distribute_args(argmap, bind.expr);
}

pub fn distribute_args(argmap: Map(*Expr), expr: *Expr) *Expr {
	switch (expr.*){
		.atom => {
			if (argmap.get(expr.atom.text)) |replacement| {
				return replacement;
			}
			return expr;
		},
		.list => {
			for (0 .. expr.list.items.len) |i| {
				expr.list.items[i] = distribute_args(argmap, expr.list.items[i]);
			}
			return expr;
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
		err.append(set_error(mem, bind.atom.pos, "Expected 3 arguments for bind special form, found {}\n", .{bind.list.items.len}))
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

//TODO IR integration
//TODO reification both ways
//TODO comp staging
//TODO comp compute hook
