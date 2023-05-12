import gdb

class LinePrinter:
    "Print a Line"

    def __init__(self, val):
        self.val = val
        self.a = val["a"]
        self.b = val["b"]

    def to_string(self):
        return f"({self.a}, {self.b})"

def lookup(val):
    lookup_tag = val.type.tag
    if lookup_tag is None:
        return None
    return LinePrinter(val) if lookup_tag == "embedded_visualizer::Line" else None

gdb.current_objfile().pretty_printers.append(lookup)
