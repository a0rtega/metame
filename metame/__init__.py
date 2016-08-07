
def main():
    import sys
    import shutil
    import metame.r2parser as r2parser
    import argparse

    parser = argparse.ArgumentParser(description="Metamorphic engine that modifies assembly code keeping the same functionality")
    parser.add_argument("-i", "--input", help="input file")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("-d", "--debug", action="store_true", help="print debug information")
    parser.add_argument("-f", "--force", action="store_true", help="force instruction replacement when possible (decreases metamorphism entropy!)")
    args = parser.parse_args()

    if not args.input or not args.output:
        parser.print_help()
        sys.exit(1)

    r = r2parser.R2Parser(args.input, True, debug=args.debug, force_replace=args.force)
    patches = r.iterate_fcn()
    r.close()

    shutil.copy(args.input, args.output)

    r = r2parser.R2Parser(args.output, False, debug=args.debug, write=True)
    r.patch_binary(patches)
    r.close()

