#!/usr/bin/env python
import sys


class PSR():
    def __init__(self, psr):
        self.content = str(bin(psr))[2:].rjust(32, '0')
        self.decode()

    def get_bits(self, start, stop):
        bits = ''
        if stop == 0:
            bits = self.content[-start-1:]
        else:
            bits = self.content[-start-1:-stop-1]

        return int(bits, 2)

    def decode(self):
        self.flags = self.get_bits(31, 26)
        self.IT10 = self.get_bits(26, 24)
        self.J = self.get_bits(24, 23)
        self.reserverd = self.get_bits(23, 20)
        self.GE = self.get_bits(19, 15)
        self.IT72 = self.get_bits(15, 9)
        self.EAIFT = self.get_bits(9, 4)
        self.M = self.get_bits(4, 0)

        self.IT = self.IT72 + self.IT10

    def __repr__(self):
        return (
            "flags: %s\n" +
            "IT: %s\n" +
            "J: %s\n" +
            "GE: %s\n" +
            "EAIFT: %s\n" +
            "M: %s\n") % (
                self.flags, self.IT, self.J, self.GE, self.EAIFT, self.M)

    def get_mode(self):

        m = {
            int('10000', 2): 'User',
            int('10001', 2): 'FIQ',
            int('10010', 2): 'IRQ',
            int('10011', 2): 'SVC',
            int('10111', 2): 'Abort',
            int('11011', 2): 'Undefined',
            int('11111', 2): 'System (ARMv4+)'
        }

        return m[self.M]

    def get_execution_state(self):
        b = (self.J << 1) + (self.EAIFT & 0x1)

        es = {
            0: 'ARM',
            1: 'Thumb',
            2: 'Jazelle-DBX',
            3: 'Thumb2-EE'
        }

        return es[b]

    def set_thumb(self):
        self.J = 0
        self.EAIFT = self.EAIFT | 0x1

    def to_int(self):
        return int(bin(self.flags)[2:] +
                   bin(self.IT10)[2:] +
                   bin(self.J)[2:] +
                   bin(self.reserverd)[2:] +
                   bin(self.GE)[2:] +
                   bin(self.IT72)[2:] +
                   bin(self.EAIFT)[2:] +
                   bin(self.M)[2:], 2)


if __name__ == "__main__":
    psr = PSR(int(sys.argv[1], 16))
    print psr
    print psr.get_mode()
    print psr.get_execution_state()
    psr.set_thumb()
    print hex(psr.to_int())
