rule info_padded_dmg
{
  meta:
    description = "Identify Apple DMG with padding between the plist and trailer sections."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.01"
    reference = "https://objective-see.org/blog/blog_0x70.html"
    DaysofYARA = "91/100"

  strings:
    $plist = "</plist>\x0a"

  condition:
    uint32be(filesize - 512) == 0x6b6f6c79 and  // "koly" trailer of DMG
    not $plist at filesize - 521  // trailer is not prefixed by property list
}
