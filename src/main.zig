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
	AT
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
	
	pub fn init(mem: *const std.mem.Allocator) Program {
		return Program {
			.binds = Map(Bind).init(mem.*),
			.mem=mem
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
						return self.evaluate(repr.items);
					}
					return candidate;
				}
			}
		}
	}

	pub fn normalize(self: *Program, normalized: *Buffer(*Expr), expr: *Expr, full: bool) ?*Expr {
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
					if (self.expect_token(normalized, &inst.list.items[1])){
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
						if (self.expect_literal(normalized, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (inst.list.items[2].* == .list){
							//TODO reify, replace with address
							normalized.append(inst)
								catch unreachable;
							continue;
						}
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
						if (self.expect_literal(normalized, &inst.list.items[2])){
							normalized.append(inst)
								catch unreachable;
							continue;
						}
						if (inst.list.items[2].* == .list){
							//TODO reify, replace with address
							normalized.append(inst)
								catch unreachable;
							continue;
						}
					}
					return null;
				},
				.ADD, .SUB, .MUL, .DIV, .MOD, .UADD, .USUB, .UMUL, .UDIV, .UMOD, .SHR, .SHL, .AND, .OR, .XOR => {
					if (inst.list.items.len != 3){
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
					return null;
				},
				.NOT, .COM, .CMP=> {
					if (inst.list.items.len != 2){
						return null;
					}
					if (self.expect_register(normalized, &inst.list.items[1])){
						if (self.expect_alu_arg(normalized, &inst.list.items[2])){
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
					if (self.expect_literal(normalized, &inst.list.items[1])){
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
					if (self.expect_alu_arg(normalized, &inst.list.items[1])){
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
					if (self.expect_register(normalized, &inst.list.items[1])){
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

	pub fn parse_ir(self: *Program, expr: *Expr) ?Buffer(ir.Instruction) {
		if (expr.* == .atom){
			return null;
		}
		if (expr.list.items.len == 0){
			return null;
		}
		var normalized = Buffer(*Expr).init(self.mem.*);
		if (self.normalize(&normalized, expr, true) == null){
			if (debug){
				std.debug.print("Failed normalization parse\n", .{});
			}
			return null;
		}
		if (debug){
			std.debug.print("Normalized:\n", .{});
			for (normalized.items) |e| {
				show_expr(e, 1);
			}
			std.debug.print("\n", .{});
		}
		//const parsed = Buffer(IRNode).init(self.mem.*);
		// TODO parse into ir.Instruction representation
		// TODO reify lists into static buffers to be written into the vm memory later
		// self normalize, then deal with register coloring, then deal with labels
		// int is special too, save registers and flatten ?
		// then parse properly
		const parsed = Buffer(ir.Instruction).init(self.mem.*);
		return parsed;
	}

	pub fn expect_alu_arg(self: *Program, normalized: *Buffer(*Expr), expr: **Expr) bool {
		return (self.expect_register(normalized, expr) or self.expect_literal(normalized, expr));
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

	pub fn expect_literal(self: *Program, normalized: *Buffer(*Expr), expr: **Expr) bool {
		if (expr.*.* == .list){
			if (self.normalize(normalized, expr.*, false)) |norm| {
				if (norm.* == .list){
					return false;
				}
				if (norm.atom.tag == .NUM){
					expr.* = norm;
					return true;
				}
			}
			return false;
		}
		if (expr.*.atom.tag == .NUM){
			return true;
		}//TODO num tokenizing
		return false;
	}

	pub fn expect_token(self: *Program, normalized: *Buffer(*Expr), expr: **Expr) bool {
		if (expr.*.* == .list){
			if (self.normalize(normalized, expr.*, false)) |norm| {
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

	pub fn evaluate(self: *Program, repr: []ir.Instruction) *Expr {
		var error_buffer = Buffer(ir.Error).init(self.mem.*);
		_ = ir.assemble_bytecode(self.mem, repr, &error_buffer) catch unreachable;
		//TODO run in context
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

pub fn apply_args(mem: *const std.mem.Allocator, expr: *Expr, bind: Bind, err: *Buffer(Error)) ParseError!*Expr {
	std.debug.assert(expr.* == .list);
	std.debug.assert(expr.list.items[0].* == .atom);
	std.debug.assert(bind.args.* == .list);
	std.debug.assert(expr.list.items.len-1 == bind.args.list.items.len); // TODO what
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
