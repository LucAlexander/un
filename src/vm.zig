const std = @import("std");
const Buffer = std.ArrayList;

const debug = true;
const debugger = true;

pub const Config = struct {
	screen_width: u64,
	screen_height: u64,
	cores: u64,
	mem_size: u64,
	mem: std.mem.Allocator
};

pub const Register = enum(u64) {
	R0=0,
	R1,
	R2,
	R3,
	R4,
	R5,
	R6,
	R7,
	R8,
	R9,
	R10,
	R11,
	IP,
	SR,
	SP,
	FP
};

const r0 = 0;
const r1 = 1;
const r2 = 2;
const r3 = 3;
const r4 = 4;
const r5 = 5;
const r6 = 6;
const r7 = 7;
const r8 = 8;
const r9 = 9;
const r10 = 10;
const r11 = 11;
const rip = 12;
const rsr = 13;
const rsp = 14;
const rfp = 15;
var kill_cores = false;
threadlocal var active_core: u64 = 0;

const Core = struct {
	reg: [16]u64,

	pub fn init(memsize: u64) Core {
		var core = Core{
			.reg=undefined
		};
		for (0..8) |i| {
			core.reg[i] = 0;
		}
		core.reg[rsp] = memsize-8;
		core.reg[rfp] = memsize-8;
		return core;
	}
};

const Memory = struct {
	mem: []u8,
	words: []align(1) u64,
	half_words: []align(1) u32,

	pub fn init(config: Config) Memory{
		var mem = Memory{
			.mem = config.mem.alloc(u8, config.mem_size) catch unreachable,
			.words = undefined,
			.half_words = undefined,
		};
		mem.words = std.mem.bytesAsSlice(u64, mem.mem[0..]);
		mem.half_words = std.mem.bytesAsSlice(u32, mem.mem[0..]);
		return mem;
	}
};

const Operation = *const fn (*VM, *Core, *align(1) u64) bool;
const Inverse = *const fn (u8, u8, u8) void;

const ContextError = error {
	NoCore
};

pub const Context = struct {
	threads: []std.Thread,
	mutex: std.Thread.Mutex,
	running: u64, // atomic
	vm: *VM,
	
	pub fn init(config: Config, vm: *VM) Context {
		kill_cores = false;
		var context = Context {
			.threads = config.mem.alloc(std.Thread, vm.cores.len) catch unreachable,
			.mutex = std.Thread.Mutex{},
			.running = 0,
			.vm=vm
		};
		for (0..vm.cores.len) |i| {
			context.threads[i] = std.Thread.spawn(.{}, core_worker, .{vm, i})
				catch unreachable;
		}
		return context;
	}

	pub fn deinit(self: *Context) void {
		kill_cores = true;
		for (0..self.threads.len) |i| {
			self.threads[i].join();
		}
	}

	pub fn awaken_core(self: *Context, start_ip: u64) ContextError!u64 {
		self.mutex.lock();
		defer self.mutex.unlock();
		for (0..self.threads.len) |core| {
			if (self.vm.cores[core].reg[rip] == 0){
				self.vm.cores[core].reg[rip] = start_ip;
				_ = @atomicRmw(u64, &self.running, .Add, 1, .seq_cst);
				if (debug){
					std.debug.print("awakened {} at {}\n", .{core, start_ip});
				}
				return core;
			}
		}
		return ContextError.NoCore;
	}

	pub fn sleep_core(self: *Context) void {
		self.mutex.lock();
		defer self.mutex.unlock();
		self.vm.cores[active_core].reg[rip] = 0;
		_ = @atomicRmw(u64, &self.running, .Sub, 1, .seq_cst);
	}

	pub fn await_cores(self: *Context) void {
		while (@atomicLoad(u64, &self.running, .seq_cst) != 0){
			std.time.sleep(1_000_000); // 1ms
		}
	}
};

pub const VM = struct {
	cores: []Core,
	memory: Memory,
	context: ?*Context,

	pub fn init(config: Config) VM {
		var vm = VM{
			.cores = config.mem.alloc(Core, config.cores) catch unreachable,
			.memory = Memory.init(config),
			.context = null
		};
		for (0..config.cores) |i| {
			vm.cores[i] = Core.init(config.mem_size);
		}
		return vm;
	}

	pub fn load_bytes(vm: *VM, address: u64, bytes: []u8) void {
		var i: u64 = address;
		for (bytes) |byte| {
			vm.memory.mem[i] = byte;
			i += 1;
		}
	}

	pub fn interpret(vm: *VM, core: u64, start: u64) void {
		vm.cores[core].reg[rip] = start;
		vm.cores[core].reg[rsp] = vm.memory.mem.len;
		var running = true;
		const ip = &vm.cores[core].reg[rip];
		const core_ptr = &vm.cores[core];
		const ops: [85]Operation = .{
			mov_rr, mov_rl, mov_rdr, 
			mov_drr, mov_drl, mov_drdr,
			add_rrr, add_rrl, add_rlr, add_rll,
			sub_rrr, sub_rrl, sub_rlr, sub_rll,
			mul_rrr, mul_rrl, mul_rlr, mul_rll,
			div_rrr, div_rrl, div_rlr, div_rll,
			mod_rrr, mod_rrl, mod_rlr, mod_rll,
			uadd_rrr, uadd_rrl, uadd_rlr, uadd_rll,
			umul_rrr, umul_rrl, umul_rlr, umul_rll,
			usub_rrr, usub_rrl, usub_rlr, usub_rll,
			udiv_rrr, udiv_rrl, udiv_rlr, udiv_rll,
			umod_rrr, umod_rrl, umod_rlr, umod_rll,
			shr_rrr, shr_rrl, shr_rlr, shr_rll,
			shl_rrr, shl_rrl, shl_rlr, shl_rll,
			and_rrr, and_rrl, and_rlr, and_rll,
			or_rrr, or_rrl, or_rlr, or_rll,
			xor_rrr, xor_rrl, xor_rlr, xor_rll,
			not_rr, not_rl,
			com_rr, com_rl,
			cmp_rr, cmp_rl,
			jmp, jeq, jle, jgt, jge, jlt, jle,
			call, ret_r, ret_l,
			psh_r, pop_r,
			int
		};
		while (running){
			if (debugger){
				const inv: [85]Inverse = .{
					inv_mov_rr, inv_mov_rl, inv_mov_rdr, 
					inv_mov_drr, inv_mov_drl, inv_mov_drdr,
					inv_add_rrr, inv_add_rrl, inv_add_rlr, inv_add_rll,
					inv_sub_rrr, inv_sub_rrl, inv_sub_rlr, inv_sub_rll,
					inv_mul_rrr, inv_mul_rrl, inv_mul_rlr, inv_mul_rll,
					inv_div_rrr, inv_div_rrl, inv_div_rlr, inv_div_rll,
					inv_mod_rrr, inv_mod_rrl, inv_mod_rlr, inv_mod_rll,
					inv_uadd_rrr, inv_uadd_rrl, inv_uadd_rlr, inv_uadd_rll,
					inv_umul_rrr, inv_umul_rrl, inv_umul_rlr, inv_umul_rll,
					inv_usub_rrr, inv_usub_rrl, inv_usub_rlr, inv_usub_rll,
					inv_udiv_rrr, inv_udiv_rrl, inv_udiv_rlr, inv_udiv_rll,
					inv_umod_rrr, inv_umod_rrl, inv_umod_rlr, inv_umod_rll,
					inv_shr_rrr, inv_shr_rrl, inv_shr_rlr, inv_shr_rll,
					inv_shl_rrr, inv_shl_rrl, inv_shl_rlr, inv_shl_rll,
					inv_and_rrr, inv_and_rrl, inv_and_rlr, inv_and_rll,
					inv_or_rrr, inv_or_rrl, inv_or_rlr, inv_or_rll,
					inv_xor_rrr, inv_xor_rrl, inv_xor_rlr, inv_xor_rll,
					inv_not_rr, inv_not_rl,
					inv_com_rr, inv_com_rl,
					inv_cmp_rr, inv_cmp_rl,
					inv_jmp, inv_jeq, inv_jle, inv_jgt, inv_jge, inv_jlt, inv_jle,
					inv_call, inv_ret_r, inv_ret_l,
					inv_psh_r, inv_pop_r,
					inv_int
				};
				const stdout = std.io.getStdOut().writer();
				stdout.print("\x1b[2J\x1b[H", .{}) catch unreachable;
				for (0..16) |i| {
					stdout.print("                                                                                       ", .{}) catch unreachable;
					stdout.print("{x:04} : ", .{(i*8)}) catch unreachable;
					for (0 .. 8) |k| {
						stdout.print("{x:02} ", .{vm.memory.mem[(i*8)+k]}) catch unreachable;
					}
					std.debug.print("\n", .{});
				}
				const bottom = core_ptr.reg[rsp]-8;
				var top = bottom + 8*16;
				if (top >= vm.memory.mem.len){
					top = vm.memory.mem.len-1;
				}
				while (top > bottom){
					stdout.print("\x1b[H", .{}) catch unreachable;
					stdout.print("                                                          ", .{}) catch unreachable;
					var issp = false;
					if (top-7 == core_ptr.reg[rsp]){
						stdout.print("\x1b[1;33m", .{}) catch unreachable;
						issp = true;
					}
					for (0..8) |_| {
						stdout.print("{x:02} ", .{vm.memory.mem[top]}) catch unreachable;
						top -= 1;
					}
					if (issp){
						stdout.print("\x1b[0m", .{}) catch unreachable;
					}
					stdout.print("\n", .{}) catch unreachable;
				}
				stdout.print("\x1b[H", .{}) catch unreachable;
				const ip_addr = ip.* << 2;
				var begin:u64 = 0;
				if (ip_addr > 4){
					begin = ip_addr - 4*4;
				}
				const end = begin + 4*16;
				while (begin < end){
					stdout.print("                            ", .{}) catch unreachable;
					var isip = false;
					if (begin == ip_addr){
						stdout.print("\x1b[1;31m", .{}) catch unreachable;
						isip = true;
					}
					const op = vm.memory.mem[begin];
					const a = vm.memory.mem[begin+1];
					const b = vm.memory.mem[begin+2];
					const c = vm.memory.mem[begin+3];
					stdout.print("{x:02} {x:02} {x:02} {x:02}     ", .{op, a, b, c}) catch unreachable;
					if (op < inv.len){
						inv[op](a, b, c);
					}
					begin += 4;
					if (isip){
						stdout.print("\x1b[0m", .{}) catch unreachable;
					}
					stdout.print("\n", .{}) catch unreachable;
				}
				stdout.print("\x1b[H", .{}) catch unreachable;
				stdout.print("r0  : {x:016}\n", .{core_ptr.reg[r0]}) catch unreachable;
				stdout.print("r1  : {x:016}\n", .{core_ptr.reg[r1]}) catch unreachable;
				stdout.print("r2  : {x:016}\n", .{core_ptr.reg[r2]}) catch unreachable;
				stdout.print("r3  : {x:016}\n", .{core_ptr.reg[r3]}) catch unreachable;
				stdout.print("r4  : {x:016}\n", .{core_ptr.reg[r4]}) catch unreachable;
				stdout.print("r5  : {x:016}\n", .{core_ptr.reg[r5]}) catch unreachable;
				stdout.print("r6  : {x:016}\n", .{core_ptr.reg[r6]}) catch unreachable;
				stdout.print("r7  : {x:016}\n", .{core_ptr.reg[r7]}) catch unreachable;
				stdout.print("r8  : {x:016}\n", .{core_ptr.reg[r8]}) catch unreachable;
				stdout.print("r9  : {x:016}\n", .{core_ptr.reg[r9]}) catch unreachable;
				stdout.print("r10 : {x:016}\n", .{core_ptr.reg[r10]}) catch unreachable;
				stdout.print("r11 : {x:016}\n", .{core_ptr.reg[r11]}) catch unreachable;
				stdout.print("fp  : {x:016}\n", .{core_ptr.reg[rfp]}) catch unreachable;
				stdout.print("\x1b[1;33msp  : {x:016}\x1b[0m\n", .{core_ptr.reg[rsp]}) catch unreachable;
				stdout.print("sr  : {x:016}\n", .{core_ptr.reg[rsr]}) catch unreachable;
				stdout.print("\x1b[1;31mip  : {x:016}\x1b[0m\n", .{core_ptr.reg[rip]}) catch unreachable;
				var stdin = std.io.getStdIn().reader();
				var buffer: [1]u8 = undefined;
				_ = stdin.read(&buffer)
					catch unreachable;
			}
			running = ops[vm.memory.half_words[ip.*]&0xFF](vm, core_ptr, ip);
		}
	}
};

pub fn core_worker(vm: *VM, thread_index: u64) void {
	active_core = thread_index;
	while (!kill_cores){
		if (vm.memory.words.len == 0){
			continue;
		}
		if (vm.cores[active_core].reg[rip] == 0){
			std.time.sleep(1_000_000); // 1ms
			continue;
		}
		vm.interpret(active_core, vm.cores[active_core].reg[rip]);
	}
}

pub fn mov_rr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mov_rr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[src];
	ip.* += 1;
	return true;
}

pub fn mov_rl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mov_rl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	const lit = (inst & 0xFFFF0000) >> 0x10;
	core.reg[reg] = lit;
	ip.* += 1;
	return true;
}

pub fn mov_rdr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mov_rdr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = vm.memory.words[core.reg[src] >> 3];
	ip.* += 1;
	return true;
}

pub fn mov_drr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mov_drr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	vm.memory.words[core.reg[dst] >> 3] = core.reg[src];
	ip.* += 1;
	return true;
}

pub fn mov_drl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mov_drl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	const lit = (inst & 0xFFFF0000) >> 0x10;
	vm.memory.words[core.reg[reg] >> 3] = lit;
	ip.* += 1;
	return true;
}

pub fn mov_drdr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mov_drdr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	vm.memory.words[core.reg[dst] >> 3] = vm.memory.words[core.reg[src] >> 3];
	ip.* += 1;
	return true;
}

pub fn add_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("add_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(sleft + sright));
	ip.* += 1;
	return true;
}

pub fn add_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("add_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @as(u64, @bitCast(sleft + sright));
	ip.* += 1;
	return true;
}

pub fn add_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("add_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(sleft + sright));
	ip.* += 1;
	return true;
}

pub fn add_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("add_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @bitCast(sleft + sright);
	ip.* += 1;
	return true;
}

pub fn sub_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("sub_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(sleft - sright));
	ip.* += 1;
	return true;
}

pub fn sub_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("sub_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @as(u64, @bitCast(sleft - sright));
	ip.* += 1;
	return true;
}

pub fn sub_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("sub_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(sleft - sright));
	ip.* += 1;
	return true;
}

pub fn sub_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("sub_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @bitCast(sleft - sright);
	ip.* += 1;
	return true;
}

pub fn mul_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mul_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(sleft * sright));
	ip.* += 1;
	return true;
}

pub fn mul_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mul_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @as(u64, @bitCast(sleft * sright));
	ip.* += 1;
	return true;
}

pub fn mul_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mul_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(sleft * sright));
	ip.* += 1;
	return true;
}

pub fn mul_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mul_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @bitCast(sleft * sright);
	ip.* += 1;
	return true;
}

pub fn div_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("div_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(@divTrunc(sleft , sright)));
	ip.* += 1;
	return true;
}

pub fn div_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("div_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @as(u64, @bitCast(@divTrunc(sleft , sright)));
	ip.* += 1;
	return true;
}

pub fn div_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("div_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(@divTrunc(sleft , sright)));
	ip.* += 1;
	return true;
}

pub fn div_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("div_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @bitCast(@divTrunc(sleft , sright));
	ip.* += 1;
	return true;
}

pub fn mod_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mod_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(@mod(sleft , sright)));
	ip.* += 1;
	return true;
}

pub fn mod_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mod_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @bitCast(core.reg[left]);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @as(u64, @bitCast(@mod(sleft , sright)));
	ip.* += 1;
	return true;
}

pub fn mod_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mod_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @bitCast(core.reg[right]);
	core.reg[dst] = @as(u64, @bitCast(@mod(sleft , sright)));
	ip.* += 1;
	return true;
}

pub fn mod_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("mod_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	const sleft: i64 = @intCast(left);
	const sright: i64 = @intCast(right);
	core.reg[dst] = @as(u64, @bitCast(@mod(sleft , sright)));
	ip.* += 1;
	return true;
}

pub fn uadd_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("uadd_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] + core.reg[right];
	ip.* += 1;
	return true;
}

pub fn uadd_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("uadd_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] + right;
	ip.* += 1;
	return true;
}

pub fn uadd_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("uadd_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left + core.reg[right];
	ip.* += 1;
	return true;
}

pub fn uadd_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("uadd_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left + right;
	ip.* += 1;
	return true;
}

pub fn usub_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("usub_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] - core.reg[right];
	ip.* += 1;
	return true;
}

pub fn usub_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("usub_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] - right;
	ip.* += 1;
	return true;
}

pub fn usub_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("usub_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left - core.reg[right];
	ip.* += 1;
	return true;
}

pub fn usub_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("usub_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left - right;
	ip.* += 1;
	return true;
}

pub fn umul_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("umul_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] * core.reg[right];
	ip.* += 1;
	return true;
}

pub fn umul_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("umul_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] * right;
	ip.* += 1;
	return true;
}

pub fn umul_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("umul_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left * core.reg[right];
	ip.* += 1;
	return true;
}

pub fn umul_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("umul_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left * right;
	ip.* += 1;
	return true;
}

pub fn udiv_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("udiv_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] / core.reg[right];
	ip.* += 1;
	return true;
}

pub fn udiv_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("udiv_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] / right;
	ip.* += 1;
	return true;
}

pub fn udiv_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("udiv_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left / core.reg[right];
	ip.* += 1;
	return true;
}

pub fn udiv_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("udiv_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left / right;
	ip.* += 1;
	return true;
}

pub fn umod_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("umod_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] % core.reg[right];
	ip.* += 1;
	return true;
}

pub fn umod_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("umod_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] % right;
	ip.* += 1;
	return true;
}

pub fn umod_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("umod_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left % core.reg[right];
	ip.* += 1;
	return true;
}

pub fn umod_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("umod_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left % right;
	ip.* += 1;
	return true;
}

pub fn shr_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("shr_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] >> @truncate(core.reg[right]);
	ip.* += 1;
	return true;
}

pub fn shr_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("shr_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] >> @truncate(right);
	ip.* += 1;
	return true;
}

pub fn shr_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("shr_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left >> @truncate(core.reg[right]);
	ip.* += 1;
	return true;
}

pub fn shr_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("shr_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left >> @truncate(right);
	ip.* += 1;
	return true;
}

pub fn shl_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("shl_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] << @truncate(core.reg[right]);
	ip.* += 1;
	return true;
}

pub fn shl_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("shl_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] << @truncate(right);
	ip.* += 1;
	return true;
}

pub fn shl_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("shl_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left << @truncate(core.reg[right]);
	ip.* += 1;
	return true;
}

pub fn shl_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("shl_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left << @truncate(right);
	ip.* += 1;
	return true;
}

pub fn and_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("and_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] & core.reg[right];
	ip.* += 1;
	return true;
}

pub fn and_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("and_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] & right;
	ip.* += 1;
	return true;
}

pub fn and_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("and_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left & core.reg[right];
	ip.* += 1;
	return true;
}

pub fn and_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("and_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left & right;
	ip.* += 1;
	return true;
}

pub fn xor_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("xor_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] ^ core.reg[right];
	ip.* += 1;
	return true;
}

pub fn xor_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("xor_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] ^ right;
	ip.* += 1;
	return true;
}

pub fn xor_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("xor_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left ^ core.reg[right];
	ip.* += 1;
	return true;
}

pub fn xor_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("xor_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left ^ right;
	ip.* += 1;
	return true;
}

pub fn or_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("or_rrr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] | core.reg[right];
	ip.* += 1;
	return true;
}

pub fn or_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("or_rrl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] | right;
	ip.* += 1;
	return true;
}

pub fn or_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("or_rlr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left | core.reg[right];
	ip.* += 1;
	return true;
}

pub fn or_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("or_rll\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left | right;
	ip.* += 1;
	return true;
}

pub fn not_rr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("not_rr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	if (core.reg[src] == 0){
		core.reg[dst] = 1;
	}
	else{
		core.reg[dst] = 0;
	}
	ip.* += 1;
	return true;
}

pub fn not_rl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("not_rl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	if (src == 0){
		core.reg[dst] = 1;
	}
	else{
		core.reg[dst] = 0;
	}
	ip.* += 1;
	return true;
}

pub fn com_rr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("com_rr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = ~core.reg[src];
	ip.* += 1;
	return true;
}

pub fn com_rl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("com_rl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = ~src;
	ip.* += 1;
	return true;
}

pub fn cmp_rr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("cmp_rr\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	if (core.reg[left] < core.reg[right]){
		core.reg[rsr] = 1;
	}
	else if (core.reg[left] > core.reg[right]){
		core.reg[rsr] = 2;
	}
	else{
		core.reg[rsr] = 0;
	}
	ip.* += 1;
	return true;
}

pub fn cmp_rl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("cmp_rl\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	if (core.reg[left] < right){
		core.reg[rsr] = 1;
	}
	else if (core.reg[left] > right){
		core.reg[rsr] = 2;
	}
	else{
		core.reg[rsr] = 0;
	}
	ip.* += 1;
	return true;
}

pub fn jmp(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("jmp\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const off:i64 = @as(i16, @bitCast(@as(u16, @truncate((inst & 0xFFFF0000) >> 0x10))));
	core.reg[rip] +%= @bitCast(off);
	return true;
}

pub fn jeq(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("jeq\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const off:i64 = @as(i16, @bitCast(@as(u16, @truncate((inst & 0xFFFF0000) >> 0x10))));
	if (core.reg[rsr] == 0){
		ip.* +%= @bitCast(off);
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jne(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("jne\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const off:i64 = @as(i16, @bitCast(@as(u16, @truncate((inst & 0xFFFF0000) >> 0x10))));
	if (core.reg[rsr] != 0){
		ip.* +%= @bitCast(off);
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jlt(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("jlt\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const off:i64 = @as(i16, @bitCast(@as(u16, @truncate((inst & 0xFFFF0000) >> 0x10))));
	if (core.reg[rsr] == 1){
		ip.* +%= @bitCast(off);
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jle(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("jle\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const off:i64 = @as(i16, @bitCast(@as(u16, @truncate((inst & 0xFFFF0000) >> 0x10))));
	if (core.reg[rsr] < 2){
		ip.* +%= @bitCast(off);
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jgt(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("jgt\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const off:i64 = @as(i16, @bitCast(@as(u16, @truncate((inst & 0xFFFF0000) >> 0x10))));
	if (core.reg[rsr] == 2){
		ip.* +%= @bitCast(off);
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jge(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("jge\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const off:i64 = @as(i16, @bitCast(@as(u16, @truncate((inst & 0xFFFF0000) >> 0x10))));
	if (core.reg[rsr] > 1){
		ip.* +%= @bitCast(off);
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn call(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("call\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const off:i64 = @as(i16, @bitCast(@as(u16, @truncate((inst & 0xFFFF0000) >> 0x10))));
	core.reg[rsp] -= 8;
	vm.memory.words[core.reg[rsp] >> 3] = core.reg[rip]+1;
	core.reg[rsp] -= 8;
	vm.memory.words[core.reg[rsp] >> 3] = core.reg[rfp];
	core.reg[rfp] = core.reg[rsp];
	core.reg[rip] +%= @bitCast(off);
	return true;
}

pub fn ret_r(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("ret_r\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	core.reg[rsp] = core.reg[rfp];
	core.reg[rfp] = vm.memory.words[core.reg[rsp] >> 3];
	core.reg[rsp] += 8;
	core.reg[rip] = vm.memory.words[core.reg[rsp] >> 3];
	vm.memory.words[core.reg[rsp] >> 3] = core.reg[reg];
	return true;
}

pub fn ret_l(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("ret_l\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const lit = (inst & 0xFF00) >> 0x8;
	core.reg[rsp] = core.reg[rfp];
	core.reg[rfp] = vm.memory.words[core.reg[rsp] >> 3];
	core.reg[rsp] += 8;
	core.reg[rip] = vm.memory.words[core.reg[rsp] >> 3];
	vm.memory.words[core.reg[rsp] >> 3] = lit;
	return true;
}

pub fn psh_r(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("psh_r\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	core.reg[rsp] -= 8;
	vm.memory.words[core.reg[rsp] >> 3] = core.reg[reg];
	ip.* += 1;
	return true;
}

pub fn pop_r(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("pop_r\n", .{});
	}
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	core.reg[reg] = vm.memory.words[core.reg[rsp] >> 3];
	core.reg[rsp] += 8;
	ip.* += 1;
	return true;
}

pub fn int(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	if (debug){
		std.debug.print("int: {}\n", .{core.reg[0]});
	}
	if (core.reg[r0] == 0){
		if (vm.context) |context| {
			context.sleep_core();
		}
		if (debug){
			std.debug.print("terminating {}\n", .{active_core});
		}
		return false;
	}
	if (core.reg[r0] == 1){
		const addr = core.reg[r1] >> 3;
		const n = vm.memory.words[addr];
		var i:u64 = 1;
		while (i <= n){
			std.debug.print("{c}", .{@as(u8, (@truncate(vm.memory.words[addr+i])))});
			i += 1;
		}
		ip.* += 1;
		return true;
	}
	if (core.reg[r0] == 2){
		if (vm.context)|context|{
			_ = context.awaken_core(core.reg[r1] >> 2) catch {};
		}
		return true;
	}
	if (core.reg[r0] == 3){
		std.debug.print("Core {} failed on user error state\n", .{active_core});
		if (vm.context) |context| {
			context.sleep_core();
		}
		if (debug){
			std.debug.print("terminating {}\n", .{active_core});
		}
		std.debug.assert(false);
	}
	if (vm.context) |context| {
		context.sleep_core();
	}
	if (debug){
		std.debug.print("unknown interrupt, ended\n", .{});
	}
	return false;
}

const ParseError = error {
	UnexpectedToken,
	UnexpectedEOF
};

pub const LArg = union(enum) {
	register: Register,
	dregister: Register,
};

pub const RArg = union(enum) {
	register: Register,
	dregister: Register,
	literal: u16
};

pub const ALUArg = union(enum) {
	register: Register,
	literal: u8
};

pub const Instruction = struct {
	tag: TOKEN,
	data: union(enum) {
		move: struct {
			dest: LArg,
			src: RArg
		},
		alu_bin: struct {
			dest: Register,
			left: ALUArg,
			right: ALUArg
		},
		alu_un: struct {
			dest: Register,
			src: ALUArg
		},
		jump: u16,
		compare: struct {
			left: Register,
			right: ALUArg
		},
		call: u16,
		ret: ALUArg,
		push: Register,
		pop: Register,
		interrupt
	}
};

pub const TOKEN = enum(u64) {
	MOV=0,
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
	NUM,
	LIT,
	OPEN,
	CLOSE,
	REG0, REG1, REG2, REG3,
	REG4, REG5, REG6, REG7,
	REG8, REG9, REG10, REG11,
	REG_FP, REG_SP,
};

const Token = struct {
	text: []u8,
	pos: u64,
	tag: TOKEN,
};

pub const Error = struct {
	message: []u8,
	pos: u64
};

pub fn set_error(mem: *const std.mem.Allocator, buffer: *Buffer(Error), index: u64, comptime fmt: []const u8, args: anytype) void {
	var err = Error{
		.pos = index,
		.message = mem.alloc(u8, 128) catch unreachable
	};
	const result = std.fmt.bufPrint(err.message, fmt, args) catch unreachable;
	err.message.len = result.len;
	buffer.append(err)
		catch unreachable;
}

pub fn tokenize(mem: *const std.mem.Allocator, text: []u8, err: *Buffer(Error)) ParseError!Buffer(Token) {
	var keywords = std.StringHashMap(TOKEN).init(mem.*);
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
	keywords.put("shr", .SHR) catch unreachable;
	keywords.put("shl", .SHL) catch unreachable;
	keywords.put("and", .AND) catch unreachable;
	keywords.put("or", .OR) catch unreachable;
	keywords.put("xor", .XOR) catch unreachable;
	keywords.put("not", .NOT) catch unreachable;
	keywords.put("com", .COM) catch unreachable;
	keywords.put("cmp", .CMP) catch unreachable;
	keywords.put("jmp", .JMP) catch unreachable;
	keywords.put("jeq", .JEQ) catch unreachable;
	keywords.put("jne", .JNE) catch unreachable;
	keywords.put("jgt", .JGT) catch unreachable;
	keywords.put("jlt", .JLT) catch unreachable;
	keywords.put("jge", .JGE) catch unreachable;
	keywords.put("jle", .JLE) catch unreachable;
	keywords.put("psh", .PSH) catch unreachable;
	keywords.put("pop", .POP) catch unreachable;
	keywords.put("call", .CALL) catch unreachable;
	keywords.put("ret", .RET) catch unreachable;
	keywords.put("int", .INT) catch unreachable;
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
	keywords.put("fp", .REG_FP) catch unreachable;
	keywords.put("sp", .REG_SP) catch unreachable;
	var i: u64 = 0;
	var tokens = Buffer(Token).init(mem.*);
	outer: while (i < text.len){
		var c = text[i];
		if (c == ' ' or c == '\n' or c == '\t'){
			i += 1;
			continue;
		}
		if (c == '!'){
			tokens.append(Token{
				.tag=.LIT,
				.pos = i,
				.text=text[i..i+1]
			}) catch unreachable;
			i += 1;
			continue;
		}
		else if (c == '['){
			tokens.append(Token{
				.tag = .OPEN,
				.pos = i,
				.text=text[i..i+1]
			}) catch unreachable;
			i += 1;
			continue;
		}
		else if (c == ']'){
			tokens.append(Token{
				.tag = .CLOSE,
				.pos = i,
				.text=text[i..i+1]
			}) catch unreachable;
			i += 1;
			continue;
		}
		const start = i;
		if (std.ascii.isAlphanumeric(c)){
			while (std.ascii.isAlphanumeric(c)) {
				i += 1;
				if (i >= text.len){
					break :outer;
				}
				c = text[i];
			}
			if (keywords.get(text[start..i])) |realtag| {
				tokens.append(Token{
					.tag = realtag,
					.text=text[start .. i],
					.pos = i
				}) catch unreachable;
				continue;
			}
			_ = std.fmt.parseInt(i32, text[start .. i], 16) catch {
				set_error(mem, err, i, "Unexpected symbol in text stream where numeric was expected: {s}\n", .{text[start..i]});
				return ParseError.UnexpectedToken;
			};
			tokens.append(Token{
				.tag = .NUM,
				.text=text[start .. i],
				.pos = i
			}) catch unreachable;
			continue;
		}
		set_error(mem, err, i, "Unexpected symbol in text stream: {c}\n", .{c});
		return ParseError.UnexpectedToken;
	}
	return tokens;
}

pub fn assert_infile(mem: *const std.mem.Allocator, tokens: []Token, i: *u64, err: *Buffer(Error)) ParseError!void {
	if (i.* >= tokens.len){
		set_error(mem, err, i.*, "Unexpected end of file in register dereference\n", .{});
		return ParseError.UnexpectedEOF;
	}
}

pub fn parse_rarg(mem: *const std.mem.Allocator, tokens: []Token, i:*u64,  err: *Buffer(Error)) ParseError!RArg {
	try assert_infile(mem, tokens, i, err);
	const ropen = tokens[i.*];
	if (ropen.tag == .OPEN){
		i.* += 1;
		const dreg = try parse_register(mem, tokens, i, err);
		try assert_infile(mem, tokens, i, err);
		const close = tokens[i.*];
		i.* += 1;
		if (close.tag != .CLOSE){
			set_error(mem, err, i.*, "Expected ] to close dereference, found {s}\n", .{close.text});
			return ParseError.UnexpectedToken;
		}
		return RArg{
			.dregister = dreg 
		};
	}
	else if (ropen.tag == .LIT){
		i.* += 1;
		try assert_infile(mem, tokens, i, err);
		const num = tokens[i.*];
		i.* += 1;
		const val = std.fmt.parseInt(u16, num.text, 16) catch {
			set_error(mem, err, i.*, "Expected 2 byte unsigned value for right arg, found {s}\n", .{num.text});
			return ParseError.UnexpectedToken;
		};
		return RArg{
			.literal = val
		};
	}
	const rreg = try parse_register(mem, tokens, i, err);
	return RArg{
		.register=rreg
	};
}

pub fn parse(mem: *const std.mem.Allocator, tokens: []Token, err: *Buffer(Error)) ParseError!Buffer(Instruction) {
	var i: u64 = 0;
	var instructions = Buffer(Instruction).init(mem.*);
	while (i < tokens.len){
		const tok = tokens[i];
		i += 1;
		switch (tok.tag){
			.MOV => {
				try assert_infile(mem, tokens, &i, err);
				const open = tokens[i];
				if (open.tag == .OPEN){
					i += 1;
					const dreg = try parse_register(mem, tokens, &i, err);
					try assert_infile(mem, tokens, &i, err);
					const close = tokens[i];
					i += 1;
					if (close.tag != .CLOSE){
						set_error(mem, err, i, "Expected ] to close dereference, found {s}\n", .{close.text});
						return ParseError.UnexpectedToken;
					}
					instructions.append(Instruction{
						.tag=tok.tag,
						.data=.{
							.move = .{
								.dest=LArg{
									.dregister=dreg
								},
								.src = try parse_rarg(mem, tokens, &i, err)
							}
						}
					}) catch unreachable;			
				}
				const reg = try parse_register(mem, tokens, &i, err);
				instructions.append(Instruction{
					.tag=tok.tag,
					.data=.{
						.move = .{
							.dest=LArg{
								.register=reg
							},
							.src = try parse_rarg(mem, tokens, &i, err)
						}
					}
				}) catch unreachable;
			},
			.ADD, .SUB, .MUL, .DIV, .MOD,
			.UADD, .USUB, .UMUL, .UDIV, .UMOD,
		  	.SHR, .SHL, .AND, .OR, .XOR  => {
				const dest = try parse_register(mem, tokens, &i, err);
				const left = try parse_alu_arg(mem, tokens, &i, err);
				const right = try parse_alu_arg(mem, tokens, &i, err);
				instructions.append(Instruction{
					.tag=tok.tag,
					.data = .{
						.alu_bin = .{
							.dest = dest,
							.left = left,
							.right = right
						}
					}
				}) catch unreachable;
			},
			.NOT, .COM => {
				const dest = try parse_register(mem, tokens, &i, err);
				const src = try parse_alu_arg(mem, tokens, &i, err);
				instructions.append(Instruction{
					.tag=tok.tag,
					.data = .{
						.alu_un = .{
							.dest = dest,
							.src = src
						}
					}
				}) catch unreachable;
			},
			.CMP => {
				const left = try parse_register(mem, tokens, &i, err);
				const right = try parse_alu_arg(mem, tokens, &i, err);
				instructions.append(Instruction{
					.tag=tok.tag,
					.data = .{
						.compare = .{
							.left = left,
							.right = right
						}
					}
				}) catch unreachable;
			},
			.JMP, .JNE, .JEQ, .JLT, .JGT, .JLE, .JGE => {
				i += 1;
				try assert_infile(mem, tokens, &i, err);
				const num = tokens[i];
				i += 1;
				const val = std.fmt.parseInt(u16, num.text, 16) catch {
					set_error(mem, err, i, "Expected 2 byte literal, found {s}\n", .{num.text});
					return ParseError.UnexpectedToken;
				};
				instructions.append(Instruction{
					.tag=tok.tag,
					.data= .{
						.jump=val
					}
				}) catch unreachable;
			},
			.PSH => {
				const reg = try parse_register(mem, tokens, &i, err);
				instructions.append(Instruction{
					.tag=tok.tag,
					.data= .{
						.push = reg
					}
				}) catch unreachable;
			},
			.POP => {
				const reg = try parse_register(mem, tokens, &i, err);
				instructions.append(Instruction{
					.tag=tok.tag,
					.data= .{
						.pop = reg
					}
				}) catch unreachable;
			},
			.CALL => {
				i += 1;
				try assert_infile(mem, tokens, &i, err);
				const num = tokens[i];
				i += 1;
				const val = std.fmt.parseInt(u16, num.text, 16) catch {
					set_error(mem, err, i, "Expected 2 byte literal, found {s}\n", .{num.text});
					return ParseError.UnexpectedToken;
				};
				instructions.append(Instruction{
					.tag=tok.tag,
					.data= .{
						.call=val
					}
				}) catch unreachable;
			},
			.RET => {
				const arg = try parse_alu_arg(mem, tokens, &i, err);
				instructions.append(Instruction{
					.tag=tok.tag,
					.data= .{
						.ret = arg
					}
				}) catch unreachable;
			},
			.INT => {
				instructions.append(Instruction{
					.tag=tok.tag,
					.data= .{
						.interrupt = undefined
					}
				}) catch unreachable;
			},
			else => {
				set_error(mem, err, i, "Unexpected token in stream, expected opcode, found {s}", .{tok.text});
				return ParseError.UnexpectedToken;
			}
		}
	}
	return instructions;
}

pub fn assemble_bytecode(mem: *const std.mem.Allocator, instructions: []Instruction, err: *Buffer(Error)) ParseError![]u8 {
	var i: u64 = 0;
	var bytes = mem.alloc(u8, instructions.len*4) catch unreachable;
	var byte: u64 = 0;
	while (i < instructions.len){
		const inst = instructions[i];
		i += 1;
		switch (inst.tag){
			.MOV => {
				if (inst.data.move.dest == .register){
					if (inst.data.move.src == .register){
						bytes[byte] = 0;
						byte += 1;
						bytes[byte] = 0;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.dest.register));
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.src.register));
						byte += 1;
						continue;
					}
					if (inst.data.move.src == .literal){
						bytes[byte] = 1;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.dest.register));
						byte += 1;
						bytes[byte] = @truncate((inst.data.move.src.literal) & 0xFF);
						byte += 1;
						bytes[byte] = @truncate((inst.data.move.src.literal & 0xFF00) >> 0x8);
						byte += 1;
						continue;
					}
					if (inst.data.move.src == .dregister){
						bytes[byte] = 2;
						byte += 1;
						bytes[byte] = 0;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.dest.register));
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.src.dregister));
						byte += 1;
						continue;
					}
				}
				else if (inst.data.move.dest == .dregister) {
					if (inst.data.move.src == .register){
						bytes[byte] = 3;
						byte += 1;
						bytes[byte] = 0;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.dest.dregister));
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.src.register));
						byte += 1;
						continue;
					}
					if (inst.data.move.src == .literal){
						bytes[byte] = 4;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.dest.dregister));
						byte += 1;
						bytes[byte] = @truncate((inst.data.move.src.literal) & 0xFF);
						byte += 1;
						bytes[byte] = @truncate((inst.data.move.src.literal & 0xFF00) >> 0x8);
						byte += 1;
						continue;
					}
					if (inst.data.move.src == .dregister){
						bytes[byte] = 5;
						byte += 1;
						bytes[byte] = 0;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.dest.dregister));
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.move.src.dregister));
						byte += 1;
						continue;
					}
				}
				unreachable;
			},
			.ADD, .SUB, .MUL, .DIV,
			.UADD, .USUB, .UMUL, .UDIV,
		  	.SHR, .SHL, .AND, .OR, .XOR  => {
				const seed:u8 = @truncate(6+((@intFromEnum(inst.tag)-1)*4));
				if (inst.data.alu_bin.left == .register){
					if (inst.data.alu_bin.right == .register){
						bytes[byte] = seed+0;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.alu_bin.dest));
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.alu_bin.left.register));
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.alu_bin.right.register));
						byte += 1;
					}
					else if (inst.data.alu_bin.right == .literal){
						bytes[byte] = seed+1;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.alu_bin.dest));
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.alu_bin.left.register));
						byte += 1;
						bytes[byte] = inst.data.alu_bin.right.literal;
						byte += 1;
					}
					continue;
				}
				else if (inst.data.alu_bin.left == .literal){
					if (inst.data.alu_bin.right == .register){
						bytes[byte] = seed+2;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.alu_bin.dest));
						byte += 1;
						bytes[byte] = inst.data.alu_bin.left.literal;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.alu_bin.right.register));
						byte += 1;
					}
					else if (inst.data.alu_bin.right == .literal){
						bytes[byte] = seed+3;
						byte += 1;
						bytes[byte] = @truncate(@intFromEnum(inst.data.alu_bin.dest));
						byte += 1;
						bytes[byte] = inst.data.alu_bin.left.literal;
						byte += 1;
						bytes[byte] = inst.data.alu_bin.right.literal;
						byte += 1;
					}
					continue;
				}
				unreachable;
			},
			.NOT, .COM => {
				const seed = 66+((@intFromEnum(inst.tag)-16)*2);
				if (inst.data.alu_un.src == .register){
					bytes[byte] = @truncate(seed);
					byte += 1;
					bytes[byte] = 0;
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.alu_un.dest));
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.alu_un.src.register));
					byte += 1;
				}
				else if (inst.data.alu_un.src == .literal){
					bytes[byte] = @truncate(seed+1);
					byte += 1;
					bytes[byte] = 0;
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.alu_un.dest));
					byte += 1;
					bytes[byte] = @truncate(inst.data.alu_un.src.literal);
					byte += 1;
				}
				continue;
			},
			.CMP => {
				if (inst.data.compare.right == .register){
					bytes[byte] = 70;
					byte += 1;
					bytes[byte] = 0;
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.compare.left));
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.compare.right.register));
					byte += 1;
				}
				else if (inst.data.compare.right == .literal){
					bytes[byte] = 71;
					byte += 1;
					bytes[byte] = 0;
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.compare.left));
					byte += 1;
					bytes[byte] = @truncate(inst.data.compare.right.literal);
					byte += 1;
				}
				continue;
			},
			.JMP, .JEQ, .JNE, .JGT, .JGE, .JLT, .JLE => {
				const seed = 72+(@intFromEnum(inst.tag)-19);
				bytes[byte] = @truncate(seed);
				byte += 1;
				bytes[byte] = 0;
				byte += 1;
				bytes[byte] = @truncate(inst.data.jump & 0xFF);
				byte += 1;
				bytes[byte] = @truncate((inst.data.jump >> 0x8) & 0xFF);
				byte += 1;
				continue;
			},
			.CALL => {
				bytes[byte] = 79;
				byte += 1;
				bytes[byte] = 0;
				byte += 1;
				bytes[byte] = @truncate((inst.data.call >> 0x8) & 0xFF);
				byte += 1;
				bytes[byte] = @truncate(inst.data.call & 0xFF);
				byte += 1;
				continue;
			},
			.RET => {
				if (inst.data.ret == .register){
					bytes[byte] = 80;
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.ret.register));
					byte += 3;
				}
				else if (inst.data.ret == .literal){
					bytes[byte] = 81;
					byte += 1;
					bytes[byte] = @truncate(inst.data.ret.literal);
					byte += 3;
				}
				continue;
			},
			.PSH => {
				bytes[byte] = 82;
				byte += 1;
				bytes[byte] = @truncate(@intFromEnum(inst.data.push));
				byte += 3;
				continue;
			},
			.POP => {
				bytes[byte] = 83;
				byte += 1;
				bytes[byte] = @truncate(@intFromEnum(inst.data.pop));
				byte += 3;
				continue;
			},
			.INT => {
				bytes[byte] = 84;
				byte += 4;
				continue;
			},
			else => {
				set_error(mem, err, i, "Unknown opcode {}\n", .{inst.tag});
				return ParseError.UnexpectedToken;
			}
		}
	}
	return bytes;
}

pub fn parse_alu_arg(mem: *const std.mem.Allocator, tokens: []Token, i: *u64, err: *Buffer(Error)) ParseError!ALUArg{
	try assert_infile(mem, tokens, i, err);
	const token = tokens[i.*];
	if (token.tag == .LIT){
		i.* += 1;
		try assert_infile(mem, tokens, i, err);
		const num = tokens[i.*];
		i.* += 1;
		const val = std.fmt.parseInt(u8, num.text, 16) catch {
			set_error(mem, err, i.*, "Expected unsigned byte for argument, found {s}\n", .{num.text});
			return ParseError.UnexpectedToken;
		};
		return ALUArg{
			.literal = val
		};
	}
	const reg = try parse_register(mem, tokens, i, err);
	return ALUArg{
		.register = reg
	};
}

pub fn parse_register(mem: *const std.mem.Allocator, tokens: []Token, i: *u64, err: *Buffer(Error)) ParseError!Register {
	try assert_infile(mem, tokens, i, err);
	const r = tokens[i.*];
	i.* += 1;
	switch (r.tag){
		.REG0 => {
			return .R0;
		},
		.REG1 => {
			return .R1;
		},
		.REG2 => {
			return .R2;
		},
		.REG3 => {
			return .R3;
		},
		.REG4 => {
			return .R4;
		},
		.REG5 => {
			return .R5;
		},
		.REG6 => {
			return .R6;
		},
		.REG7 => {
			return .R7;
		},
		.REG8 => {
			return .R8;
		},
		.REG9 => {
			return .R9;
		},
		.REG10 => {
			return .R10;
		},
		.REG11 => {
			return .R11;
		},
		.REG_FP => {
			return .FP;
		},
		.REG_SP => {
			return .SP;
		},
		else => {
			set_error(mem, err, i.*, "Expected register, found {s}\n", .{r.text});
			return ParseError.UnexpectedToken;
		}
	}
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

pub fn show_bytecode(bytes: []u8) void {
	for (0 .. bytes.len/4) |i| {
		const index = i * 4;
		std.debug.print("{x:02} {x:02} {x:02} {x:02}\n", .{
			bytes[index],
			bytes[index+1],
			bytes[index+2],
			bytes[index+3]
		});
	}
}

pub fn testmain() !void {
	const allocator = std.heap.page_allocator;
	const default_config = Config {
		.screen_width = 320,
		.screen_height = 180,
		.cores = 4,
		.mem_size = 0x100000,
		.mem = allocator
	};
	var infile = std.fs.cwd().openFile("test.bit", .{}) catch {
		std.debug.print("File not found {s}\n", .{"test.bit"});
		return;
	};
	defer infile.close();
	const stat = infile.stat() catch {
		std.debug.print("Errored file stat: {s}\n", .{"test.bit"});
		return;
	};
	const contents = infile.readToEndAlloc(allocator, stat.size+1) catch {
		std.debug.print("Error reading file: {s}\n", .{"test.bit"});
		return;
	};
	defer allocator.free(contents);
	var err = Buffer(Error).init(allocator);
	const tokens = tokenize(&allocator, contents, &err) catch {
		for (err.items) |e| {
			show_error(contents, e);
		}
		return;
	};
	const instructions = parse(&allocator, tokens.items, &err) catch {
		for (err.items) |e| {
			show_error(contents, e);
		}
		return;
	};
	const bytecode = assemble_bytecode(&allocator, instructions.items, &err) catch {
		for (err.items) |e| {
			show_error(contents, e);
		}
		return;
	};
	show_bytecode(bytecode);
	with(default_config, bytecode, 0x200);
}

pub fn with(config:Config, bytecode: []u8, start: u64) void {
	var vm = VM.init(config);
	vm.load_bytes(start, bytecode);
	var context = Context.init(config, &vm);
	vm.context = &context;
	_ = context.awaken_core(start>>2) catch {
		std.debug.print("Corrupted VM state\n", .{});
		context.deinit();
	};
	context.await_cores();
	context.deinit();
}

pub fn write_register(reg: u8) void {
	const stdout = std.io.getStdOut().writer();
	switch (reg) {
		0 => {stdout.print("r0 ", .{}) catch unreachable;},
		1 => {stdout.print("r1 ", .{}) catch unreachable;},
		2 => {stdout.print("r2 ", .{}) catch unreachable;},
		3 => {stdout.print("r3 ", .{}) catch unreachable;},
		4 => {stdout.print("r4 ", .{}) catch unreachable;},
		5 => {stdout.print("r5 ", .{}) catch unreachable;},
		6 => {stdout.print("r6 ", .{}) catch unreachable;},
		7 => {stdout.print("r7 ", .{}) catch unreachable;},
		8 => {stdout.print("r8 ", .{}) catch unreachable;},
		9 => {stdout.print("r9 ", .{}) catch unreachable;},
		10 => {stdout.print("r10 ", .{}) catch unreachable;},
		11 => {stdout.print("r11 ", .{}) catch unreachable;},
		12 => {stdout.print("rip ", .{}) catch unreachable;},
		13 => {stdout.print("rsr ", .{}) catch unreachable;},
		14 => {stdout.print("rsp ", .{}) catch unreachable;},
		15 => {stdout.print("rfp ", .{}) catch unreachable;},
		else => {
			unreachable;
		}
	}
}

pub fn write_dregister(reg: u8) void {
	const stdout = std.io.getStdOut().writer();
	switch (reg) {
		0 => {stdout.print("*r0 ", .{}) catch unreachable;},
		1 => {stdout.print("*r1 ", .{}) catch unreachable;},
		2 => {stdout.print("*r2 ", .{}) catch unreachable;},
		3 => {stdout.print("*r3 ", .{}) catch unreachable;},
		4 => {stdout.print("*r4 ", .{}) catch unreachable;},
		5 => {stdout.print("*r5 ", .{}) catch unreachable;},
		6 => {stdout.print("*r6 ", .{}) catch unreachable;},
		7 => {stdout.print("*r7 ", .{}) catch unreachable;},
		8 => {stdout.print("*r8 ", .{}) catch unreachable;},
		9 => {stdout.print("*r9 ", .{}) catch unreachable;},
		10 => {stdout.print("*r10 ", .{}) catch unreachable;},
		11 => {stdout.print("*r11 ", .{}) catch unreachable;},
		12 => {stdout.print("*rip ", .{}) catch unreachable;},
		13 => {stdout.print("*rsr ", .{}) catch unreachable;},
		14 => {stdout.print("*rsp ", .{}) catch unreachable;},
		15 => {stdout.print("*rfp ", .{}) catch unreachable;},
		else => {
			unreachable;
		}
	}
}

pub fn write_lit8(c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("{x:02} ", .{c}) catch unreachable;
}

pub fn write_lit16(b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	const lit = (@as(u16, @intCast(b)) << 8) | c;
	stdout.print("{x:04} ", .{lit}) catch unreachable;
}

pub fn inv_mov_rr(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mov ", .{}) catch unreachable;
	write_register(b);
	write_register(c);
}

pub fn inv_mov_rl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mov ", .{}) catch unreachable;
	write_register(a);
	write_lit16(b, c);
}

pub fn inv_mov_rdr(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mov ", .{}) catch unreachable;
	write_register(b);
	write_dregister(c);
}

pub fn inv_mov_drr(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mov ", .{}) catch unreachable;
	write_dregister(b);
	write_register(c);
}

pub fn inv_mov_drl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mov ", .{}) catch unreachable;
	write_dregister(a);
	write_lit16(b, c);
}

pub fn inv_mov_drdr(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mov ", .{}) catch unreachable;
	write_dregister(b);
	write_dregister(c);
}

pub fn inv_add_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("add ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_add_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("add ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_add_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("add ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_add_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("add ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_sub_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("sub ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_sub_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("sub ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_sub_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("sub ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_sub_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("sub ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_mul_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mul ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_mul_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mul ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_mul_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mul ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_mul_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mul ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_div_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("div ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_div_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("div ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_div_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("div ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_div_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("div ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_mod_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mod ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_mod_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mod ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_mod_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mod ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_mod_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("mod ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_uadd_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("uadd ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_uadd_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("uadd ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_uadd_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("uadd ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_uadd_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("uadd ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_usub_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("usub ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_usub_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("usub ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_usub_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("usub ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_usub_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("usub ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_umul_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("umul ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_umul_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("umul ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_umul_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("umul ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_umul_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("umul ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_udiv_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("udiv ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_udiv_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("udiv ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_udiv_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("udiv ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_udiv_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("udiv ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_umod_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("umod ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_umod_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("umod ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_umod_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("umod ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_umod_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("umod ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_shl_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("shl ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_shl_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("shl ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_shl_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("shl ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_shl_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("shl ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_shr_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("shr ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_shr_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("shr ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_shr_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("shr ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_shr_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("shr ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_and_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("and ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_and_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("and ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_and_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("and ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_and_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("and ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_xor_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("xor ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_xor_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("xor ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_xor_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("xor ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_xor_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("xor ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_or_rrr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("or ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_register(c);
}

pub fn inv_or_rrl(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("or ", .{}) catch unreachable;
	write_register(a);
	write_register(b);
	write_lit8(c);
}

pub fn inv_or_rlr(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("or ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_register(c);
}

pub fn inv_or_rll(a: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("or ", .{}) catch unreachable;
	write_register(a);
	write_lit8(b);
	write_lit8(c);
}

pub fn inv_not_rr(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("not ", .{}) catch unreachable;
	write_register(b);
	write_register(c);
}

pub fn inv_not_rl(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("not ", .{}) catch unreachable;
	write_register(b);
	write_lit8(c);
}

pub fn inv_com_rr(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("com ", .{}) catch unreachable;
	write_register(b);
	write_register(c);
}

pub fn inv_com_rl(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("com ", .{}) catch unreachable;
	write_register(b);
	write_lit8(c);
}

pub fn inv_cmp_rr(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("cmp ", .{}) catch unreachable;
	write_register(b);
	write_register(c);
}

pub fn inv_cmp_rl(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("cmp ", .{}) catch unreachable;
	write_register(b);
	write_lit8(c);
}

pub fn inv_jmp(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("jmp ", .{}) catch unreachable;
	write_lit16(b, c);
}

pub fn inv_jeq(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("jeq ", .{}) catch unreachable;
	write_lit16(b, c);
}

pub fn inv_jne(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("jne ", .{}) catch unreachable;
	write_lit16(b, c);
}

pub fn inv_jlt(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("jlt ", .{}) catch unreachable;
	write_lit16(b, c);
}

pub fn inv_jle(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("jle ", .{}) catch unreachable;
	write_lit16(b, c);
}

pub fn inv_jgt(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("jgt ", .{}) catch unreachable;
	write_lit16(b, c);
}

pub fn inv_jge(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("jge ", .{}) catch unreachable;
	write_lit16(b, c);
}

pub fn inv_call(_: u8, b: u8, c: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("call ", .{}) catch unreachable;
	write_lit16(b, c);
}

pub fn inv_ret_r(a: u8, _: u8, _: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("re t", .{}) catch unreachable;
	write_register(a);
}

pub fn inv_ret_l(a: u8, _: u8, _: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("ret ", .{}) catch unreachable;
	write_lit8(a);
}

pub fn inv_psh_r(a: u8, _: u8, _: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("psh ", .{}) catch unreachable;
	write_register(a);
}

pub fn inv_pop_r(a: u8, _: u8, _: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("pop ", .{}) catch unreachable;
	write_register(a);
}

pub fn inv_int(_: u8, _: u8, _: u8) void {
	const stdout = std.io.getStdOut().writer();
	stdout.print("int ", .{}) catch unreachable;
}

