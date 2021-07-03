import gdb

class Offsets(gdb.Command):
    def __init__(self):
        super(Offsets, self).__init__('offsets-of', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if len(argv) != 1:
            raise gdb.GdbError('offsets-of take exactly 1 argument.')

        self.print_offsets(argv[0], gdb.lookup_type(argv[0]))

    def print_offsets(self, name, stype, prefix=""):
        print('%s%s {' % (prefix, name))
        for field in stype.fields():
            if hasattr(field, 'bitpos') and field.bitpos is not None:
                offset = '%4d (0x%04x)' % (field.bitpos//8, field.bitpos//8)
            else:
                offset = '---- (0x----)'

            if hasattr(field.type, 'sizeof') and field.type.sizeof is not None:
                size = '%3d (0x%02x)' % (field.type.sizeof, field.type.sizeof)
            else:
                size = '---- (0x----)'

            if hasattr(field.type, 'name') and field.type.name:
                typename = '   : ' + field.type.name
            else:
                typename = ''

            print('%s  %s / %s => %s%s' % (prefix, offset, size, field.name, typename))

            if field.is_base_class:
                self.print_offsets(field.name, field.type, prefix + "     ")

        print('%s}' % prefix)
        print('%sTotal size: %d (0x%04x) bytes' % (prefix, stype.sizeof, stype.sizeof))

Offsets()

