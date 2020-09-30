import gdb

class Offsets(gdb.Command):
    def __init__(self):
        super(Offsets, self).__init__('offsets-of', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if len(argv) != 1:
            raise gdb.GdbError('offsets-of take exactly 1 argument.')

        stype = gdb.lookup_type(argv[0])

        print(argv[0], '{')
        for field in stype.fields():
            if hasattr(field, 'bitpos'):
                offset = '%4d (0x%04x)' % (field.bitpos//8, field.bitpos//8)
            else:
                offset = '---- (0x----)'

            if hasattr(field.type, 'name') and field.type.name:
                typename = '   : ' + field.type.name
            else:
                typename = ''

            print('  %s => %s%s' % (offset, field.name, typename))

        print('}')
        print('Total size: %d (0x%04x) bytes' % (stype.sizeof, stype.sizeof))

Offsets()

