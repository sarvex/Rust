import gdb

class PersonPrinter:
    "Print a Person"

    def __init__(self, val):
        self.val = val
        self.name = val["name"]
        self.age = int(val["age"])

    def to_string(self):
        return f"{self.name} is {self.age} years old."

def lookup(val):
    lookup_tag = val.type.tag
    if lookup_tag is None:
        return None
    if lookup_tag == "dependency_with_embedded_visualizers::Person":
        return PersonPrinter(val)

    return None

gdb.current_objfile().pretty_printers.append(lookup)
