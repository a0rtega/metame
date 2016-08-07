# metame

metame is a simple metamorphic code engine for arbitrary executables.

From Wikipedia:

> Metamorphic code is code that when run outputs a logically equivalent
> version of its own code under some interpretation.
> This is used by computer viruses to avoid the pattern recognition of
> anti-virus software.

metame implementation works this way:

1. Open a given binary and analyze the code
2. Randomly replace instructions with equivalences in logic and size
3. Copy and patch the original binary to generate a mutated variant

It currently supports the following architectures:

- x86 32 bits
- x86 64 bits

Also, it supports a variety of file formats, as [radare2][1] is used for
file parsing and code analysis.

Example of code before and after mutation:

![alt text](https://raw.githubusercontent.com/a0rtega/metame/master/screens/screen1.png "Spot the differences")

Hint: Two instructions have been replaced in this snippet.

Here another example on how it can mutate a NOP sled into equivalent code:

![alt text](https://raw.githubusercontent.com/a0rtega/metame/master/screens/screen2.png "Spot the differences")

## Installation

```
pip install metame
```

This should also install the requirements.

You will also need [radare2][1]. Refer to the official website for
installation instructions.

`simplejson` is also a "nice to have" for a small performance
boost:

```
pip install simplejson
```

## Usage

```
metame -i original.exe -o mutation.exe -d
```

Use `metame -h` for help.

## License

This project is released under the terms of the MIT license.

[1]: http://radare.org/

