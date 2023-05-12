import gdb

class PointPrinter:
    "Print a Point"

    def __init__(self, val):
        self.val = val
        self.x = int(val["x"])
        self.y = int(val["y"])

    def to_string(self):
        return f"({self.x}, {self.y})"

def lookup(val):
    lookup_tag = val.type.tag
    if lookup_tag is None:
        return None
    if lookup_tag == "embedded_visualizer::point::Point":
        return PointPrinter(val)

    return None

gdb.current_objfile().pretty_printers.append(lookup)
