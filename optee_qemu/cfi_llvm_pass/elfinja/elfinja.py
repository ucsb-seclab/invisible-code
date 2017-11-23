import os
import tempfile
from filebytes.elf import *
import logging

PAGE_SIZE = 4096

LOG = logging.getLogger("elfinja")


class ELFinja(object):
    """ELFinja short for ELF-inject-a"""

    def __init__(self, filename):
        self.original_filename = filename
        self.elf = ELF(filename)

        self._ephemeral_files = []

    def n_inject(self, n, newcode):
        """Overwrite an arbitrary segment
        :param n: nth segment to overwrite, is -1 add segments after the other (but it can overwrite existing code/data)
        :param newcode: string of code to inject
        """

        assert n < len(self.elf.programHeaders), "n out of bounds"
        assert n >= -1

        # find max address of any load segment
        max_load_addr = 0
        for phdr in self.elf.programHeaders:
            if phdr.header.p_type == PT.LOAD.value:
                load_addr = phdr.header.p_vaddr + phdr.header.p_memsz
                if load_addr > max_load_addr:
                    max_load_addr = load_addr

        if n == -1:
            eh = self.elf.elfHeader
            original_content = "".join(map(chr,self.elf._bytes))
            new_header_pos = eh.header.e_phoff + eh.header.e_phnum * eh.header.e_phentsize
            dummy_header = "\x00"*eh.header.e_phentsize
            new_content = original_content[:new_header_pos] + dummy_header + \
                    original_content[new_header_pos+len(dummy_header):]
            self.elf = ELF(self.original_filename,fileContent=new_content)
            #now we can add 1 to e_phnum
            #before it would have generated an exception trying to parse random data
            self.elf.elfHeader.header.e_phnum += 1
            new_content2 = "".join(map(chr,self.elf._bytes))
            self.elf = ELF(self.original_filename,fileContent=new_content2)
            n = self.elf.elfHeader.header.e_phnum - 1

        inject_phdr = self.elf.programHeaders[n]

        inject_addr = (max_load_addr + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE

        file_sz = len(self.elf._bytes)
        padded_host_size = (file_sz + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE

        LOG.debug("inject_addr: %#x", inject_addr)
        LOG.debug("padded_host_size: %#x", padded_host_size)


        # overwrite the header
        inject_phdr.header.p_type = PT.LOAD.value
        inject_phdr.header.p_flags = PF.READ.value | PF.EXEC.value | PF.WRITE.value
        inject_phdr.header.p_vaddr = inject_addr
        inject_phdr.header.p_paddr = inject_addr
        inject_phdr.header.p_filesz = len(newcode)
        inject_phdr.header.p_memsz = len(newcode)
        inject_phdr.header.p_align = 1
        inject_phdr.header.p_offset = padded_host_size


        tf = tempfile.mktemp(prefix='elfinja-', dir='/tmp/' )
        self._ephemeral_files.append(tf)
        with open(tf, 'wb') as f:
            f.write(self.elf._bytes)
            f.seek(padded_host_size - file_sz, 1)
            f.write(newcode)

        self.elf = ELF(tf)
        return (inject_phdr.header.p_offset,inject_phdr.header.p_vaddr)

    def n_patch_section(self, n, vaddr, paddr, size):
        """Patch the section table so that IDA is happy.
        Since IDA does not automatically load some sections (e.g., .note...), you still need to select the manually load option.
        """
        assert n < len(self.elf.sections), "n out of bounds"
        assert n >= 0

        ss = self.elf.sections[n]
        hh = ss.header
        hh.sh_addr = vaddr
        hh.sh_offset = paddr
        hh.sh_size = size
        hh.sh_flags = PF.READ.value | PF.EXEC.value | PF.WRITE.value

        tf = tempfile.mktemp(prefix='elfinja-', dir='/tmp/' )
        self._ephemeral_files.append(tf)
        with open(tf, 'wb') as f:
            f.write(self.elf._bytes)

        self.elf = ELF(tf)

    def dump_segments(self):
        def pflags_to_perms(p_flags):
            pf_x = (1 << 0)
            pf_w = (1 << 1)
            pf_r = (1 << 2)

            perms = ""
            if p_flags & pf_r:
                perms += "R"
            if p_flags & pf_w:
                perms += "W"
            if p_flags & pf_x:
                perms += "X"
            return perms

        def type_to_str(type_num,enum):
            for t in dir(enum):
                if t.startswith("_"):
                    continue
                tt = enum.__dict__[t]
                if(type_num == tt.value):
                    return tt.name+" (%08x)"%tt.value
            return str(type_num)

        def header_to_str(header):
            tstr = "%25s % 16x % 16x % 16x % 16x % 16x %4s % 8x" % \
                    (type_to_str(header.p_type,PT), header.p_offset, header.p_vaddr, header.p_paddr,
                    header.p_filesz, header.p_memsz, pflags_to_perms(header.p_flags), \
                    header.p_align)
            return tstr

        header_strs = []
        for i,p in enumerate(self.elf.programHeaders):
            header_strs.append("%2s: "%i + header_to_str(p.header))
        tstr = "\n".join(header_strs) + "\n"
        eh = self.elf.elfHeader
        tstr += "Headers between: 0x%x and 0x%x\n" % \
                (eh.header.e_phoff, eh.header.e_phoff + eh.header.e_phnum * eh.header.e_phentsize)
        tstr += "ELF bits: %s, Endianness: %s, Architecture: %s\n" % \
                (type_to_str(eh.header.e_ident[5],ELFCLASS),type_to_str(eh.header.e_ident[6],ELFDATA),type_to_str(eh.header.e_machine,EM))

        return tstr

    def dump_sections(self):
        def pflags_to_perms(p_flags):
            pf_x = (1 << 0)
            pf_w = (1 << 1)
            pf_r = (1 << 2)

            perms = ""
            if p_flags & pf_r:
                perms += "R"
            if p_flags & pf_w:
                perms += "W"
            if p_flags & pf_x:
                perms += "X"
            return perms

        def header_to_str(section):
            hh = p.header
            tstr = "%25s % 16x % 16x % 16x % 16x %4s % 8x" % \
                    (p.name, hh.sh_addr, hh.sh_offset, hh.sh_size, hh.sh_entsize,
                    pflags_to_perms(hh.sh_flags), hh.sh_addralign)
            return tstr

        header_strs = []
        for i,p in enumerate(self.elf.sections):
            header_strs.append("%2s: "%i + header_to_str(p))
        tstr = "\n".join(header_strs) + "\n"

        return tstr

    def note_inject(self, newcode, fix_segments=False):
        """Inject code into an ELF file.

        Uses Jacopo's NOTE injection technique
        :param newcode: string of code to inject
        """

        # find max address of any load segment and...
        # find the note program header
        note_phdr_offset = None
        for i, phdr in enumerate(self.elf.programHeaders):
            if phdr.header.p_type == PT.NOTE.value:
                note_phdr_offset = i

        assert note_phdr_offset is not None, "No NOTE segment"

        paddr, vaddr = self.n_inject(note_phdr_offset, newcode)
        sname = ""
        if fix_segments:
            for i, ss in enumerate(self.elf.sections):
                if ss.name.startswith(".note"):
                    sn = i
                    sname = ss.name
                    break
            else:
                assert False, "No .note section"
            self.n_patch_section(sn, vaddr, paddr, len(newcode))

        return paddr, vaddr, sname

    def patch_bytes(self, vaddr, byte_s):
        """Inject bytes at an already existing address

        :param vaddr: virtual address to inject bytes at
        :param byte_s: byte string to inject
        """

        # double check virtual address
        vpage = vaddr & (2**32 - PAGE_SIZE)
        voff = vaddr & PAGE_SIZE

        c_segment = None
        for seg in self.elf.segments:
            seg_vpage = seg.vaddr & (2**32 - PAGE_SIZE)

            # found
            if vpage > seg_vpage:
                if vaddr + len(byte_s) < seg.vaddr + len(seg.bytes):
                    c_segment = seg
                    break

        assert c_segment is not None, "Bad vaddr, does not exist"

        offset = vaddr - c_segment.vaddr

        for i, o in enumerate(range(offset, offset+len(byte_s))):
            c_segment.raw[o] = ord(byte_s[i])

        tf = tempfile.mktemp(prefix='elfinja-', dir='/tmp/' )
        self._ephemeral_files.append(tf)
        with open(tf, 'wb') as f:
            f.write(self.elf._bytes)

    def writeout(self, filename):

        with open(filename, 'wb') as f:
            f.write(self.elf._bytes)
        os.chmod(filename, 0755)

    def __del__(self):

        for ephemeral in self._ephemeral_files:
            os.remove(ephemeral)
