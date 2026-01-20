# un

Hello,

Un is an experimental meta compiler substrate research project. A few things to note:
* The implementation is not optimal, and it does not produce optimal bytecode. 
* The implementation is research grade, not industry grade, it currently does not produce native binaries, although the resulting bytecode can be trivially translated to a target architecture of choice if you the user desires. 
* The language is not meant to be used as is, it's a backend + an experimental set of metacomputation structures for which the user is meant to implement a compiler frontend to utilized the experimental features.
* The key feature being experimented with is language constraints as first class structures, everything else is secondary and is only implemented in support of or as a base for this feature. Do not expect the data structures or algorithms used in these cases to be flawless, they are meant to be minimal. 

The expected use case for this tool is experimentation with novel language features, and it is built to promote fast iteration times. Writing constraints like type systems, borrow checkers, capability systems, proof engines, and effect systems is being optimized, but other areas of compiler research are possible. Register allocation and lowering is handled, and the target is a 64 bit bytecode VM meant to be as tiny as possible while faithfully emulating how modern CPU arhcitectures typically work. This VM is missing some interrupts, but is fully capable of concurrent programming. Tokenization/Parsing have been ignored, as they are trivial endeavors. 

The basic premise is that the language provides a intermediate representation, and a series of simple meta primitives to compose the instructions in this representation to infinitely extend the surface area of the language. There is full reification and reflection between the high level s expression environment used for meta computation, and the runtime bytecode environment.

# Special Forms


(bind name args body)

(uid list_of_uid_aliases body)

(flat list)

(comp vm_name (body))

(use path)

# Base IR

```
(reg x)
(mov x (at x))
(mov (at x) x)
(mov x ffff)
(mov (at x) ffff)

```

```
(add x x 7)
(add x 1 4)
```

Binary ops: add sub mul div mod uadd usub umul udiv umod and or xor shl shr
Unary ops: not com

```
(reg x)
(mov x 0)
(label loop)
    (cmp x 5)
    (jge exit)
    (add x x 1)
    (jmp label)
(label exit)
```

You can jump with jmp, jeq, jne, jlt, jgt, jle, jge
Calls work with (call name) and do stack manipuation

```
(psh x)
(pop x)

(ret 7)
(ret x)
```

Reify higher level structures with reif:
```
(reif x (a b c))
(reif x "hello")
(reif x ffffffff)
```

create unique identifiers with (uid list block)

```
(uid (loop i) (
    (reg i)
    (mov i 0)
    (label loop)
    ...
))
```

You can ncest expressions as long as they have a terminal symbol

```
(mov x (
    (reg y)
    (mov y 7)
    (y)
))
```



