rule HalfandHalfLoader
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "A rule detecting HalfandHalf's signature zipper obfuscation - is there a less performance intensive way to find this?"
        version = "1.0"
        date = "2023-02-01"
        reference1="https://www.bleepingcomputer.com/news/security/sodinokibi-ransomware-spreads-via-fake-forums-on-hacked-sites/"
        reference2="https://news.sophos.com/en-us/2021/03/01/gootloader-expands-its-payload-delivery-options/"

    strings:
        $function = /n.o.i.t.c.n.u.f/
        $try = /{.y.r.t/
        $constructor = /r.o.t.c.u.r.t.s.n.o.c/
    condition:
        all of them
}
