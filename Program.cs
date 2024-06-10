
using System.ComponentModel;

enum Register
{
    R0 = 0x2,
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
    R12,
    R13,
    R14,
    R15,
    R16,
    R17,
    R18,
    R19,
    R20,
    R21,
    R22,
    R23,
    R24,
    R25,
    R26,
    R27,
    R28,
    R29,
    R30,
    R31,
    R32,
    R33,
    R34,
    R35,
    R36,
    R37,
    R38,
    R39,
    R40,
    R41,
    R42,
    R43,
    R44,
    R45,
    R46,
    R47,
    R48,
    R49,
    R50,
    R51,
    R52,
    R53,
    R54,
    R55,
    R56,
    R57,
    R58,
    R59,
    R60,
    R61,
    R62,
    R63,
    SP,
    PC,
}

enum Opcode
{
    _UNDEFINED,
    ADD,
    SUB,
    MUL,
    DIV,
    MOD,
    SHL,
    SHR,
    AND,
    OR,
    XOR,
    NOT,
    JMP,
    JE,
    JNE,
    JG,
    JL,
    JGE,
    JLE,
    CMP,
    MOV,
    PUSH,
    POP,
    RET,
    CALL,
    SYSCALL,
    HALT,
    NOP
}

enum Interrupt
{
    UNDEFINED,
    DIV_BY_ZERO,
    STACK_OVERFLOW,
    STACK_UNDERFLOW,
    SEGMENTATION_FAULT,
    TIMER,
    KEYBOARD,
}

enum CompareFlag
{
    EQ,
    NE,
    GT,
    LT,
}

enum Syscall
{
    WRITE,
    READ,
    FLUSH,
    SEEK,
    TELL,
    OPEN,
    CLOSE
}

class FileDescriptor
{
    public FileStream? handle;
    public byte[] buffer = new byte[0x1000];
    public int n_written = 0;
}

class VM
{
    public ulong[] gp = new ulong[64];
    public ulong sp;
    public ulong pc;
    public ulong current_insn;
    public byte[] memory;
    public ulong stack_size;
    public ulong[] idt = new ulong[32];
    public bool[] interrupt_pending = new bool[32];
    public CompareFlag cmp_flag = CompareFlag.NE;
    public bool running = true;
    public FileDescriptor[] fd_table = new FileDescriptor[0x10]; // First 2 are reserved for stdout/stdin

    public void raise_interrupt(Interrupt interrupt, bool jump = false)
    {
        Console.WriteLine("debug: raising interrupt " + interrupt);
        if (jump)
        {
            push_u64(current_insn);
            pc = idt[(int)interrupt];
        }
        else
        {
            interrupt_pending[(int)interrupt] = true;
        }
    }

    public ref ulong get_register(ulong b)
    {
        Register reg = (Register)(b & 0xFF);
        if (reg < Register.R0 || reg > Register.PC)
        {
            raise_interrupt(Interrupt.UNDEFINED, true);
        }
        if (reg == Register.SP)
        {
            return ref sp;
        }
        if (reg == Register.PC)
        {
            Console.WriteLine("debug: returned program counter");
            return ref pc;
        }
        // Console.WriteLine("r" + reg);
        return ref gp[(int)reg - 0x2];
    }

    public ulong get_reg_or_imm(ulong b, bool increment = true)
    {
        bool type = ((b & 0x8000000000000000) >> 63) != 0;
        // Console.WriteLine("debug: type " + type);
        if (type == false)
        {
            // Console.WriteLine("Imm: " + b + ", pc: " + pc);
            if (increment)
            {
                pc += 8;
            }
            return b & 0x7FFFFFFFFFFFFFFF;
        }
        if (increment)
        {
            pc += 8;
        }
        return get_register(b);
    }

    public bool verify_addr(ulong addr)
    {
        return addr >= 0 && addr < (ulong)memory.Length;
    }

    public ulong fetch_u64(ulong addr)
    {
        return
            (ulong)(memory[addr + 7] << 56 | memory[addr + 6] << 48 | memory[addr + 5] << 40 | memory[addr + 4] << 32 | memory[addr + 3] << 24 | memory[addr + 2] << 16 | memory[addr + 1] << 8 | memory[addr]);
    }

    public uint fetch_u32(ulong addr)
    {
        return
            (uint)(memory[addr + 3] << 24 | memory[addr + 2] << 16 | memory[addr + 1] << 8 | memory[addr]);
    }

    public ushort fetch_u16(ulong addr)
    {
        return
            (ushort)(memory[addr + 1] << 8 | memory[addr]);
    }

    public byte fetch_u8(ulong addr)
    {
        return memory[addr];
    }

    public void store_u64(ulong addr, ulong value)
    {
        memory[addr + 7] = (byte)(value >> 56);
        memory[addr + 6] = (byte)(value >> 48);
        memory[addr + 5] = (byte)(value >> 40);
        memory[addr + 4] = (byte)(value >> 32);
        memory[addr + 3] = (byte)(value >> 24);
        memory[addr + 2] = (byte)(value >> 16);
        memory[addr + 1] = (byte)(value >> 8);
        memory[addr] = (byte)(value);
    }

    public void store_u32(ulong addr, uint value)
    {
        memory[addr + 3] = (byte)(value >> 24);
        memory[addr + 2] = (byte)(value >> 16);
        memory[addr + 1] = (byte)(value >> 8);
        memory[addr] = (byte)(value);
    }

    public void store_u16(ulong addr, ushort value)
    {
        memory[addr + 1] = (byte)(value >> 8);
        memory[addr] = (byte)(value);
    }

    public void store_u8(ulong addr, byte value)
    {
        memory[addr] = value;
    }

    public void push_u64(ulong value)
    {
        store_u64(sp, value);
        sp -= 8;
    }

    public ulong pop_u64()
    {
        sp += 8;
        return fetch_u64(sp);
    }

    public void push_u32(uint value)
    {
        store_u32(sp, value);
        sp -= 4;
    }

    public uint pop_u32()
    {
        sp += 4;
        return fetch_u32(sp);
    }

    public void push_u16(ushort value)
    {
        store_u16(sp, value);
        sp -= 2;
    }

    public ushort pop_u16()
    {
        sp += 2;
        return fetch_u16(sp);
    }

    public void push_u8(byte value)
    {
        store_u8(sp, value);
        sp -= 1;
    }

    public byte pop_u8()
    {
        sp += 1;
        return fetch_u8(sp);
    }

    public VM(ulong total_mem, ulong stack_size, List<byte> code)
    {
        Console.WriteLine("Total mem: " + total_mem);
        memory = new byte[total_mem];
        if ((ulong)code.Count > total_mem)
        {
            throw new Exception("Code too long");
        }
        for (int i = 0; i < code.Count; i++)
        {
            memory[i] = code[i];
        }
        sp = total_mem - stack_size;
        pc = 0;
        this.stack_size = stack_size;
        for (int i = 0; i < 32; i++)
        {
            idt[i] = 0;
        }
        for (int i = 0; i < 64; i++)
        {
            gp[i] = 0;
        }
        fd_table[0] = new FileDescriptor();
        fd_table[1] = new FileDescriptor();
    }

    public void write_fd(int fd, byte[] buf, ulong len)
    {
        for (ulong i = 0; i < len; i++)
        {
            fd_table[fd].buffer[fd_table[fd].n_written] = buf[i];
            fd_table[fd].n_written++;
        }
    }

    public void read_fd(int fd, ulong addr, ulong len)
    {
        if (fd > 2)
        {
            byte[] buf = new byte[len];
            fd_table[fd].handle?.Read(buf, 0, (int)len);
            for (ulong i = 0; i < len; i++)
            {
                store_u8(addr + i, buf[i]);
            }
        }
    }

    public void flush_fd(int fd)
    {
        if (fd == 0)
        {
            Console.Write(fd_table[fd].buffer[..fd_table[fd].n_written]);
        }
        else if (fd > 2)
        {
            fd_table[fd].handle?.Write(fd_table[fd].buffer[..fd_table[fd].n_written], 0, (int)fd_table[fd].n_written);
        }
        fd_table[fd].buffer = new byte[0x1000];
        fd_table[fd].n_written = 0;
    }

    public int find_free_fd()
    {
        for (int i = 2; i < 0x10; i++)
        {
            if (fd_table[i].handle == null)
            {
                return i;
            }
        }
        return -1;
    }

    public int open_fd(string path)
    {
        FileStream handle = File.Open(path, FileMode.OpenOrCreate);
        int fd = find_free_fd();
        fd_table[fd].handle = handle;
        return fd;
    }

    public void close_fd(int fd)
    {
        fd_table[fd].handle?.Close();
        fd_table[fd].handle = null;
    }

    public void step()
    {
        Opcode opcode = (Opcode)fetch_u8(pc);
        Console.WriteLine("debug: opcode " + opcode);
        current_insn = pc;
        pc++;
        switch (opcode)
        {
            case Opcode.NOP:
                break;
            case Opcode.ADD:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2 + r3;
                    break;
                }
            case Opcode.SUB:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2 - r3;
                    break;
                }
            case Opcode.MUL:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2 * r3;
                    break;
                }
            case Opcode.DIV:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    if (r3 == 0)
                    {
                        raise_interrupt(Interrupt.DIV_BY_ZERO, true);
                    }
                    r1 = r2 / r3;
                    break;
                }
            case Opcode.MOD:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    if (r3 == 0)
                    {
                        raise_interrupt(Interrupt.DIV_BY_ZERO, true);
                    }
                    r1 = r2 % r3;
                    break;
                }
            case Opcode.SHL:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2 << (int)r3;
                    break;
                }
            case Opcode.SHR:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2 >> (int)r3;
                    break;
                }
            case Opcode.AND:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2 & r3;
                    break;
                }
            case Opcode.OR:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2 | r3;
                    break;
                }
            case Opcode.XOR:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r3 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2 ^ r3;
                    break;
                }
            case Opcode.NOT:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc += 8;
                    r1 = ~r1;
                    break;
                }
            case Opcode.JMP:
                {
                    ulong addr = get_reg_or_imm(fetch_u64(pc), false);
                    pc = addr;
                    break;
                }
            case Opcode.JE:
                {
                    if (cmp_flag == CompareFlag.EQ)
                    {
                        ulong addr = get_reg_or_imm(fetch_u64(pc), false);
                        pc = addr;
                    }
                    break;
                }
            case Opcode.JNE:
                {
                    if (cmp_flag != CompareFlag.EQ)
                    {
                        ulong addr = get_reg_or_imm(fetch_u64(pc), false);
                        pc = addr;
                    }
                    break;
                }
            case Opcode.JG:
                {
                    if (cmp_flag == CompareFlag.GT)
                    {
                        ulong addr = get_reg_or_imm(fetch_u64(pc), false);
                        pc = addr;
                    }
                    break;
                }
            case Opcode.JL:
                {
                    if (cmp_flag == CompareFlag.LT)
                    {
                        ulong addr = get_reg_or_imm(fetch_u64(pc), false);
                        pc = addr;
                    }
                    break;
                }
            case Opcode.JGE:
                {
                    if (cmp_flag == CompareFlag.EQ || cmp_flag == CompareFlag.GT)
                    {
                        ulong addr = get_reg_or_imm(fetch_u64(pc), false);
                        pc = addr;
                    }
                    break;
                }
            case Opcode.JLE:
                {
                    if (cmp_flag == CompareFlag.LT || cmp_flag == CompareFlag.EQ)
                    {
                        ulong addr = get_reg_or_imm(fetch_u64(pc), false);
                        pc = addr;
                    }
                    break;
                }
            case Opcode.CMP:
                {
                    ulong r1 = get_reg_or_imm(fetch_u64(pc), true);
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    if (r1 == r2)
                    {
                        cmp_flag = CompareFlag.EQ;
                    }
                    else if (r1 > r2)
                    {
                        cmp_flag = CompareFlag.GT;
                    }
                    else if (r1 < r2)
                    {
                        cmp_flag = CompareFlag.LT;
                    }
                    break;
                }
            case Opcode.MOV:
                {
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc++;
                    ulong r2 = get_reg_or_imm(fetch_u64(pc), true);
                    r1 = r2;
                    break;
                }
            case Opcode.PUSH:
                {
                    ulong value = get_reg_or_imm(fetch_u64(pc), true);
                    push_u64(value);
                    break;
                }
            case Opcode.POP:
                {
                    ulong value = pop_u64();
                    ref ulong r1 = ref get_register(fetch_u64(pc));
                    pc++;
                    r1 = value;
                    break;
                }
            case Opcode.RET:
                {
                    ulong value = pop_u64();
                    pc = value;
                    break;
                }
            case Opcode.CALL:
                {
                    ulong addr = get_reg_or_imm(fetch_u64(pc), true);
                    push_u64(pc);
                    pc = addr;
                    break;
                }
            case Opcode.SYSCALL:
                {
                    int syscall_num = (int)(gp[0] & 0xFF);
                    do_syscall(syscall_num);
                    break;
                }
            case Opcode.HALT:
                {
                    running = false;
                    break;
                }
            case Opcode._UNDEFINED:
                {
                    Console.WriteLine("debug: undefined opcode");
                    running = false;
                    break;
                }
            default:
                {
                    Console.WriteLine("debug: invalid opcode" + opcode);
                    raise_interrupt(Interrupt.UNDEFINED, false);
                    break;
                }
        }
    }

    public void do_syscall(int syscall_num)
    {
        switch (syscall_num)
        {
            case (int)Syscall.WRITE:
                {
                    int fd = (int)gp[1];
                    ulong buf = gp[2];
                    ulong len = gp[3];
                    break;
                }
            case (int)Syscall.READ:
                {
                    int fd = (int)gp[1];
                    ulong buf = gp[2];
                    ulong len = gp[3];
                    break;
                }
            case (int)Syscall.FLUSH:
                {
                    break;
                }
            case (int)Syscall.SEEK:
                {
                    break;
                }
            case (int)Syscall.TELL:
                {
                    break;
                }
            case (int)Syscall.OPEN:
                {
                    break;
                }
            case (int)Syscall.CLOSE:
                {
                    break;
                }
        }
    }
}

public enum TokenType
{
    NUM,
    REG,
    LABEL,
    OPCODE,
    EOF,
}
public class Token
{
    public TokenType type;
    public string value;
}

public class Tokenizer
{
    public List<Token> tokens;
    public string code;
    public int pos;

    public Tokenizer(string code)
    {
        this.code = code;
        tokens = new List<Token>();
        pos = 0;
    }

    bool is_alphanumeric(char c)
    {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    string get_next_word()
    {
        string word = "";
        while (pos < code.Length && is_alphanumeric(code[pos]))
        {
            word += code[pos];
            pos++;
        }
        return word;
    }

    void eliminate_whitespace(bool comments)
    {
        while (pos < code.Length && (code[pos] == ' ' || code[pos] == '\t' || (comments && code[pos] == ';')))
        {
            if (code[pos] == ';' && comments)
            {
                while (pos < code.Length && code[pos] != '\n')
                {
                    pos++;
                }
                return;
            }
            pos++;
        }
    }

    public Token reg_or_imm()
    {
        if (code[pos] == 'r' || (code[pos] == 'p' && code[pos + 1] == 'c') || (code[pos] == 's' && code[pos + 1] == 'p'))
        {
            return new Token { type = TokenType.REG, value = get_next_word() };
        }
        else
        {
            return new Token { type = TokenType.NUM, value = get_next_word() };
        }
    }

    public void tokenize()
    {
        while (pos < code.Length)
        {
            string word = get_next_word();
            if (word == "")
            {
                pos++;
            }
            else
            {
                try
                {
                    if (code[pos++] == ':')
                    {
                        tokens.Add(new Token { type = TokenType.LABEL, value = word }); eliminate_whitespace(true);
                        continue;
                    }
                }
                catch (IndexOutOfRangeException)
                {
                }
                switch (word)
                {
                    case "nop":
                    case "halt":
                    case "syscall":
                        {
                            Console.WriteLine("opcode: " + word);
                            tokens.Add(new Token { type = TokenType.OPCODE, value = word });
                            eliminate_whitespace(true);
                            break;
                        }
                    case "add":
                    case "sub":
                    case "mul":
                    case "div":
                    case "mod":
                    case "shl":
                    case "shr":
                    case "and":
                    case "or":
                    case "xor":
                        {
                            tokens.Add(new Token { type = TokenType.OPCODE, value = word });
                            eliminate_whitespace(false);
                            tokens.Add(reg_or_imm()); eliminate_whitespace(false);
                            tokens.Add(reg_or_imm()); eliminate_whitespace(false);
                            tokens.Add(reg_or_imm());
                            eliminate_whitespace(true);
                            break;
                        }
                    case "cmp":
                    case "mov":
                        {
                            tokens.Add(new Token { type = TokenType.OPCODE, value = word });
                            eliminate_whitespace(false);
                            tokens.Add(reg_or_imm()); eliminate_whitespace(false);
                            tokens.Add(reg_or_imm());
                            eliminate_whitespace(true);
                            break;
                        }
                    case "jmp":
                    case "je":
                    case "jne":
                    case "jge":
                    case "jle":
                    case "push":
                    case "pop":
                    case "call":
                        {
                            tokens.Add(new Token { type = TokenType.OPCODE, value = word });
                            eliminate_whitespace(false);
                            tokens.Add(reg_or_imm());
                            eliminate_whitespace(true);
                            break;
                        }
                    default:
                        {
                            Console.WriteLine("Invalid opcode at " + pos);
                            break;
                        }
                }
            }
        }
    }
}

class Assembler
{
    public Dictionary<string, ulong> labels;
    public List<Token> tokens;
    public List<byte> code;

    public Assembler(List<Token> tokens)
    {
        this.tokens = tokens;
        labels = new Dictionary<string, ulong>();
        code = new List<byte>();
    }

    public void assemble(ulong min_size = 0)
    {
        foreach (Token token in tokens)
        {
            if (token.type == TokenType.LABEL)
            {
                labels[token.value] = (ulong)code.Count;
            }
            if (token.type == TokenType.OPCODE)
            {
                byte op = 0xFF;
                switch (token.value)
                {
                    case "nop":
                        op = (byte)Opcode.NOP;
                        break;
                    case "halt":
                        op = (byte)Opcode.HALT;
                        break;
                    case "syscall":
                        op = (byte)Opcode.SYSCALL;
                        break;
                    case "add":
                        op = (byte)Opcode.ADD;
                        break;
                    case "sub":
                        op = (byte)Opcode.SUB;
                        break;
                    case "mul":
                        op = (byte)Opcode.MUL;
                        break;
                    case "div":
                        op = (byte)Opcode.DIV;
                        break;
                    case "mod":
                        op = (byte)Opcode.MOD;
                        break;
                    case "shl":
                        op = (byte)Opcode.SHL;
                        break;
                    case "shr":
                        op = (byte)Opcode.SHR;
                        break;
                    case "and":
                        op = (byte)Opcode.AND;
                        break;
                    case "or":
                        op = (byte)Opcode.OR;
                        break;
                    case "xor":
                        op = (byte)Opcode.XOR;
                        break;
                    case "not":
                        op = (byte)Opcode.NOT;
                        break;
                    case "jmp":
                        op = (byte)Opcode.JMP;
                        break;
                    case "je":
                        op = (byte)Opcode.JE;
                        break;
                    case "jne":
                        op = (byte)Opcode.JNE;
                        break;
                    case "jge":
                        op = (byte)Opcode.JGE;
                        break;
                    case "jle":
                        op = (byte)Opcode.JLE;
                        break;
                    case "cmp":
                        op = (byte)Opcode.CMP;
                        break;
                    case "mov":
                        op = (byte)Opcode.MOV;
                        break;
                    case "push":
                        op = (byte)Opcode.PUSH;
                        break;
                    case "pop":
                        op = (byte)Opcode.POP;
                        break;
                    case "ret":
                        op = (byte)Opcode.RET;
                        break;
                    case "call":
                        op = (byte)Opcode.CALL;
                        break;
                    default:
                        Console.WriteLine("this should not happen");
                        break;
                }
                code.Add(op);
            }
            if (token.type == TokenType.REG)
            {
                ulong b = 0x0;
                if (token.value[0] == 'r')
                {
                    int index = int.Parse(token.value[1..]);
                    b = (ulong)(index + 0x2);
                }
                else if (token.value == "pc")
                {
                    b = (ulong)Register.PC;
                }
                else if (token.value == "sp")
                {
                    b = (ulong)Register.SP;
                }
                b |= (ulong)1 << 63;
                code.AddRange(BitConverter.GetBytes(b));
            }
            if (token.type == TokenType.NUM)
            {
                ulong num = ulong.Parse(token.value) & 0x7FFFFFFFFFFFFFFF;
                code.AddRange(BitConverter.GetBytes(num));
            }
        }
        Console.WriteLine("Assembled " + code.Count + " bytes");
    }
}

public class Program
{
    public static void Main(string[] args)
    {
        string code = File.ReadAllText(args[0]);
        Tokenizer tokenizer = new Tokenizer(code);
        tokenizer.tokenize();

        foreach (Token token in tokenizer.tokens)
        {
            Console.WriteLine(token.type + " " + token.value);
        }

        Console.WriteLine("");

        Assembler assembler = new Assembler(tokenizer.tokens);
        assembler.assemble();

        FileStream bin = new FileStream("binary.bin", FileMode.OpenOrCreate);
        bin.Write(assembler.code.ToArray());
        bin.Close();

        VM vm = new VM(0x10000, 0x1000, assembler.code);

        while (vm.running)
        {
            try
            {
                vm.step();
            }
            catch (IndexOutOfRangeException)
            {
                Opcode failedOp = (Opcode)vm.fetch_u8(vm.current_insn);
                Console.WriteLine("Failed opcode: " + failedOp);
                break;
            }
        }

        for (int i = 0; i < vm.gp.Length; i += 4)
        {
            Console.WriteLine("r" + i + ": " + vm.gp[i] + "\t" + "r" + (i + 1) + ": " + vm.gp[i + 1] + "\t" + "r" + (i + 2) + ": " + vm.gp[i + 2] + "\t" + "r" + (i + 3) + ": " + vm.gp[i + 3]);
        }

        Console.WriteLine("pc: " + vm.pc);
        Console.WriteLine("sp: " + vm.sp);
        Console.WriteLine("cmp_flag: " + vm.cmp_flag);
    }
}

