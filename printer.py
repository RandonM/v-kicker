import os
import sys

# This class is based on the study of
# https://github.com/derv82/wifite2/blob/master/wifite/util/color.py

class Printer(object):
    go_up_char = '\x1B[1F'

    console_colors = {
        'W' : '\033[00m', # White
        'R' : '\033[31m', # Red
        'G' : '\033[32m', # Green
        'B' : '\033[34m', # Blue
        'C' : '\033[36m', # Cyan
        'Y' : '\033[33m', # Yellow
        'M' : '\033[35m', # Magenta
    }

    modes = {
        '{!}': ' {C}[{G}!{C}]{W}',
        '{?}': ' {C}[{Y}?{C}]{W}',
        '{x}': ' {Y}[{R}x{Y}]{Y}'
    }

    @staticmethod
    def write(message):
        parsed = Printer.parse_color(message)
        sys.stdout.write(parsed)
        sys.stdout.flush()

    @staticmethod
    def writeline(message):
        Printer.write("%s\n" % message)

    @staticmethod
    def parse_color(message):
        output = message

        for (k, v) in Printer.modes.items():
            output = output.replace(k, v)

        for (k, v) in Printer.console_colors.items():
            output = output.replace("{%s}" % k, v)

        return output

    @staticmethod
    def go_up(rows):
        Printer.writeline(Printer.go_up_char * (rows + 1))

    @staticmethod
    def clear_line():
        (rows, columns) = os.popen('stty size', 'r').read().split()
        Printer.write('\r' + (' ' * int(columns)) + '\r')