Im not set on the name, doesn't really matter ultimately.

# un

This is iteration something of my metacomputation tooling. This iteration uses s expressions for the meta compilation and a bytecode language for the base computation substrate. 

# Special forms

(bind name args body)

(uid list_of_uid_aliases body)

(flat list)

(comp vm_name (body))

(use path)

# IR

(reg x)
(mov x (at x))
(mov (at x) x)
(mov x ffff)
(mov (at x) ffff)

get it so far?

(add x x 7)
(add x 1 4)

Binary ops: add sub mul div mod uadd usub umul udiv umod and or xor shl shr
Unary ops: not com

(reg x)
(mov x 0)
(label loop)
    (cmp x 5)
    (jge exit)
    (add x x 1)
    (jmp label)
(label exit)

You can jump with jmp, jeq, jne, jlt, jgt, jle, jge
Calls work with (call name) and do stack manipuation

(psh x)
(pop x)

(ret 7)
(ret x)


Reify higher level structures with reif:
(reif x (a b c))
(reif x "hello")
(reif x ffffffff)

create unique identifiers with (uid list block)

(uid (loop i) (
    (reg i)
    (mov i 0)
    (label loop)
    ...
))

You can ncest expressions as long as they have a terminal symbol

(mov x (
    (reg y)
    (mov y 7)
    (y)
))


