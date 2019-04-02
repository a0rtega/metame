
import metame.x86handler as x86handler
import metame.constants as constants

import r2pipe
try:
    import simplejson as json
except:
    import json

class R2Parser:
    def __init__(self, filename, anal, debug=False, force_replace=False, write=False):
        self.debug = debug
        self.force = force_replace
        flags = ["-q"]
        if write:
            flags.append("-w")
        print("[INFO] Opening file with r2")
        self.r2 = r2pipe.open(filename, flags)
        info = json.loads(self.r2.cmd("ij").replace("\\", "\\\\"))
        if "bin" not in info.keys():
            raise Exception("[ERROR] File type not supported")
        if not info["bin"]["bits"] in constants.supported_bits or \
           not info["bin"]["arch"] in constants.supported_archs:
            raise Exception("[ERROR] Architecture not supported")
        self.arch = info["bin"]["arch"]
        self.bits = info["bin"]["bits"]
        if anal:
            print("[INFO] Analyzing functions with r2")
            self.r2.cmd("aaa")

    def iterate_fcn(self):
        if self.arch == "x86":
            arch = x86handler.X86Handler(self.bits, self.debug, self.force)
        replacements = []
        print("[INFO] Loading functions information")
        fcns = json.loads(self.r2.cmd("aflj"))
        print("[INFO] Replacing instructions")
        for f in fcns:
            if f["type"] == "fcn":
                try:
                    fcn_ctx = json.loads(self.r2.cmd("pdfj @%s" % f["name"]))
                except:
                    print("[ERROR] Error disassembling function %s" % f["name"])
                replacements += arch.replace_fcn_opcodes(fcn_ctx)
        return replacements

    def patch_binary(self, patches):
        print("[INFO] Patching binary")
        for w in patches:
            self.r2.cmd("wx %s @%s" % (w["newbytes"], w["offset"]))
        print("[INFO] Done, number of instructions changed: %s" % (len(patches)))

    def close(self):
        self.r2.quit()

