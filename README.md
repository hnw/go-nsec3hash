nsec3hash(1) — generate NSEC3 hash
=================

## SYNOPSIS

```
nsec3hash <salt> <algorithm> <iterations> <domain>
```

or

```
nsec3hash <domain>
```

## DESCRIPTION

nsec3hash generates an NSEC3 hash based on a set of NSEC3 parameters. This can be used to check the validity of NSEC3 records in a signed zone.

## ARGUMENTS

<dl>
  <dt>salt</dt>
  <dd>The salt provided to the hash algorithm.</dd>

  <dt>algorithm</dt>
  <dd>A number indicating the hash algorithm. Currently the only supported hash algorithm for NSEC3 is SHA-1, which is indicated by the number 1; consequently "1" is the only useful value for this argument.</dd>

  <dt>iterations</dt>
  <dd>The number of additional times the hash should be performed.</dd>

  <dt>domain</dt>
  <dd>The domain name to be hashed.</dd>
</dl>

## EXAMPLE

``` shell
$ nsec3hash github.com

$ nsec3hash - 0 0 github.com

```

## References

* [BIND](https://www.isc.org/downloads/bind/)
* [miekg/dns: DNS library in Go](https://github.com/miekg/dns)

## LICENSE

The MIT License

Copyright (c) 2016 Yoshio HANAWA

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
