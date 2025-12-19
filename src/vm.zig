const std = @import("std");
const Buffer = std.ArrayList;

const debug = true;

const Config = struct {
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
	IP,
	SR,
	SP,
	FP
};

const r0 = 0;
const r1 = 1;
const r2 = 2;
const r3 = 3;
const rip = 4;
const rsr = 5;
const rsp = 6;
const rfp = 7;
var kill_cores = false;
threadlocal var active_core: u64 = 0;

const Core = struct {
	reg: [8]u64,

	pub fn init() Core {
		var core = Core{
			.reg=undefined
		};
		for (0..8) |i| {
			core.reg[i] = 0;
		}
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

const ContextError = error {
	NoCore
};

const Context = struct {
	threads: []std.Thread,
	mutex: std.Thread.Mutex,
	running: u64, // atomic
	vm: *VM,
	
	pub fn init(config: Config, vm: *VM) Context {
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
					std.debug.print("awakeded {}\n", .{core});
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

const VM = struct {
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
			vm.cores[i] = Core.init();
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
			mul_rrr, mul_rrl, mul_rlr, mul_rll,
			sub_rrr, sub_rrl, sub_rlr, sub_rll,
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
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[src];
	ip.* += 1;
	return true;
}

pub fn mov_rl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	const lit = (inst & 0xFFFF0000) >> 0x10;
	core.reg[reg] = lit;
	ip.* += 1;
	return true;
}

pub fn mov_rdr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = vm.memory.words[core.reg[src]];
	ip.* += 1;
	return true;
}

pub fn mov_drr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	vm.memory.words[core.reg[dst]] = core.reg[src];
	ip.* += 1;
	return true;
}

pub fn mov_drl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	const lit = (inst & 0xFFFF0000) >> 0x10;
	vm.memory.words[core.reg[reg]] = lit;
	ip.* += 1;
	return true;
}

pub fn mov_drdr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	vm.memory.words[core.reg[dst]] = vm.memory.words[core.reg[src]];
	ip.* += 1;
	return true;
}

pub fn add_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] + core.reg[right];
	ip.* += 1;
	return true;
}

pub fn add_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] + right;
	ip.* += 1;
	return true;
}

pub fn add_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left + core.reg[right];
	ip.* += 1;
	return true;
}

pub fn add_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left + right;
	ip.* += 1;
	return true;
}

pub fn sub_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] - core.reg[right];
	ip.* += 1;
	return true;
}

pub fn sub_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] - right;
	ip.* += 1;
	return true;
}

pub fn sub_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left - core.reg[right];
	ip.* += 1;
	return true;
}

pub fn sub_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left - right;
	ip.* += 1;
	return true;
}

pub fn mul_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] * core.reg[right];
	ip.* += 1;
	return true;
}

pub fn mul_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] * right;
	ip.* += 1;
	return true;
}

pub fn mul_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left * core.reg[right];
	ip.* += 1;
	return true;
}

pub fn mul_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left * right;
	ip.* += 1;
	return true;
}

pub fn div_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] / core.reg[right];
	ip.* += 1;
	return true;
}

pub fn div_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] / right;
	ip.* += 1;
	return true;
}

pub fn div_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left / core.reg[right];
	ip.* += 1;
	return true;
}

pub fn div_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left / right;
	ip.* += 1;
	return true;
}

pub fn mod_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] % core.reg[right];
	ip.* += 1;
	return true;
}

pub fn mod_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] % right;
	ip.* += 1;
	return true;
}

pub fn mod_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left % core.reg[right];
	ip.* += 1;
	return true;
}

pub fn mod_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left % right;
	ip.* += 1;
	return true;
}

pub fn uadd_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] + core.reg[right];
	ip.* += 1;
	return true;
}

pub fn uadd_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] + right;
	ip.* += 1;
	return true;
}

pub fn uadd_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left + core.reg[right];
	ip.* += 1;
	return true;
}

pub fn uadd_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left + right;
	ip.* += 1;
	return true;
}

pub fn usub_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] - core.reg[right];
	ip.* += 1;
	return true;
}

pub fn usub_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] - right;
	ip.* += 1;
	return true;
}

pub fn usub_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left - core.reg[right];
	ip.* += 1;
	return true;
}

pub fn usub_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left - right;
	ip.* += 1;
	return true;
}

pub fn umul_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] * core.reg[right];
	ip.* += 1;
	return true;
}

pub fn umul_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] * right;
	ip.* += 1;
	return true;
}

pub fn umul_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left * core.reg[right];
	ip.* += 1;
	return true;
}

pub fn umul_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left * right;
	ip.* += 1;
	return true;
}

pub fn udiv_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] / core.reg[right];
	ip.* += 1;
	return true;
}

pub fn udiv_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] / right;
	ip.* += 1;
	return true;
}

pub fn udiv_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left / core.reg[right];
	ip.* += 1;
	return true;
}

pub fn udiv_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left / right;
	ip.* += 1;
	return true;
}

pub fn umod_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] % core.reg[right];
	ip.* += 1;
	return true;
}

pub fn umod_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] % right;
	ip.* += 1;
	return true;
}

pub fn umod_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left % core.reg[right];
	ip.* += 1;
	return true;
}

pub fn umod_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left % right;
	ip.* += 1;
	return true;
}

pub fn shr_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] >> @truncate(core.reg[right]);
	ip.* += 1;
	return true;
}

pub fn shr_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] >> @truncate(right);
	ip.* += 1;
	return true;
}

pub fn shr_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left >> @truncate(core.reg[right]);
	ip.* += 1;
	return true;
}

pub fn shr_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left >> @truncate(right);
	ip.* += 1;
	return true;
}

pub fn shl_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] << @truncate(core.reg[right]);
	ip.* += 1;
	return true;
}

pub fn shl_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] << @truncate(right);
	ip.* += 1;
	return true;
}

pub fn shl_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left << @truncate(core.reg[right]);
	ip.* += 1;
	return true;
}

pub fn shl_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left << @truncate(right);
	ip.* += 1;
	return true;
}

pub fn and_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] & core.reg[right];
	ip.* += 1;
	return true;
}

pub fn and_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] & right;
	ip.* += 1;
	return true;
}

pub fn and_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left & core.reg[right];
	ip.* += 1;
	return true;
}

pub fn and_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left & right;
	ip.* += 1;
	return true;
}

pub fn xor_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] ^ core.reg[right];
	ip.* += 1;
	return true;
}

pub fn xor_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] ^ right;
	ip.* += 1;
	return true;
}

pub fn xor_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left ^ core.reg[right];
	ip.* += 1;
	return true;
}

pub fn xor_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left ^ right;
	ip.* += 1;
	return true;
}

pub fn or_rrr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] | core.reg[right];
	ip.* += 1;
	return true;
}

pub fn or_rrl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = core.reg[left] | right;
	ip.* += 1;
	return true;
}

pub fn or_rlr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left | core.reg[right];
	ip.* += 1;
	return true;
}

pub fn or_rll(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x0000FF00) >> 0x8;
	const left = (inst & 0x00FF0000) >> 0x10;
	const right = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = left | right;
	ip.* += 1;
	return true;
}

pub fn not_rr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
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
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = ~core.reg[src];
	ip.* += 1;
	return true;
}

pub fn com_rl(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const dst = (inst & 0x00FF0000) >> 0x10;
	const src = (inst & 0xFF000000) >> 0x18;
	core.reg[dst] = ~src;
	ip.* += 1;
	return true;
}

pub fn cmp_rr(vm: *VM, core: *Core, ip: *align(1) u64) bool {
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
	const inst = vm.memory.half_words[ip.*];
	const off = (inst & 0xFFFF0000) >> 0x10;
	core.reg[rip] += off;
	return true;
}

pub fn jeq(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const off = (inst & 0xFFFF0000) >> 0x10;
	if (core.reg[rsr] == 0){
		ip.* += off;
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jne(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const off = (inst & 0xFFFF0000) >> 0x10;
	if (core.reg[rsr] != 0){
		ip.* += off;
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jlt(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const off = (inst & 0xFFFF0000) >> 0x10;
	if (core.reg[rsr] == 1){
		ip.* += off;
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jle(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const off = (inst & 0xFFFF0000) >> 0x10;
	if (core.reg[rsr] < 2){
		ip.* += off;
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jgt(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const off = (inst & 0xFFFF0000) >> 0x10;
	if (core.reg[rsr] == 2){
		ip.* += off;
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn jge(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const off = (inst & 0xFFFF0000) >> 0x10;
	if (core.reg[rsr] > 1){
		ip.* += off;
		return true;
	}
	ip.* += 1;
	return true;
}

pub fn call(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const off = (inst & 0xFFFF0000) >> 0x10;
	core.reg[rsp] -= 8;
	vm.memory.words[core.reg[rsp] >> 3] = core.reg[rip]+1;
	core.reg[rsp] -= 8;
	vm.memory.words[core.reg[rsp] >> 3] = core.reg[rfp];
	core.reg[rfp] = core.reg[rsp];
	core.reg[rip] += off;
	return true;
}

pub fn ret_r(vm: *VM, core: *Core, ip: *align(1) u64) bool {
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
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	core.reg[rsp] = core.reg[rfp];
	core.reg[rsp] -= 8;
	vm.memory.words[core.reg[rsp] >> 3] = core.reg[reg];
	ip.* += 1;
	return true;
}

pub fn pop_r(vm: *VM, core: *Core, ip: *align(1) u64) bool {
	const inst = vm.memory.half_words[ip.*];
	const reg = (inst & 0xFF00) >> 0x8;
	core.reg[rsp] = core.reg[rfp];
	core.reg[reg] = vm.memory.words[core.reg[rsp] >> 3];
	core.reg[rsp] += 8;
	ip.* += 1;
	return true;
}

pub fn int(vm: *VM, core: *Core, _: *align(1) u64) bool {
	if (core.reg[r0] == 0){
		if (vm.context) |context| {
			context.sleep_core();
		}
		if (debug){
			std.debug.print("terminating {}\n", .{active_core});
		}
		return false;
	}
	return true;
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
						bytes[byte] = @truncate((inst.data.move.src.literal & 0xFF00) >> 0x8);
						byte += 1;
						bytes[byte] = @truncate((inst.data.move.src.literal) & 0xFF);
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
						bytes[byte] = @truncate((inst.data.move.src.literal & 0xFF00) >> 0x8);
						byte += 1;
						bytes[byte] = @truncate((inst.data.move.src.literal) & 0xFF);
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
				const seed = 64+((@intFromEnum(inst.tag)-16)*2);
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
					bytes[byte] = 76;
					byte += 1;
					bytes[byte] = 0;
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.compare.left));
					byte += 1;
					bytes[byte] = @truncate(@intFromEnum(inst.data.compare.right.register));
					byte += 1;
				}
				else if (inst.data.compare.right == .literal){
					bytes[byte] = 77;
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
				bytes[byte] = 78;
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
				bytes[byte] = @truncate(inst.data.call & 0xFF);
				byte += 1;
				bytes[byte] = @truncate((inst.data.call >> 0x8) & 0xFF);
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

//TODO decoder
//TODO debugger
//TODO distinction between signed and unsigned math
//TODO make offset jumps signed in the interpreter portion
