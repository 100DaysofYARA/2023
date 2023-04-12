rule file_ipsw
{
  meta:
    description = "Identify Apple iPhone Software (.ipsw) files"
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.29"
    reference = "http://newosxbook.com/bonus/vol1AppA.html"
    DaysofYARA = "88/100"

  strings:
    $s0 = "Restore.plist"
    $s1 = "BuildManifest.plist"
    $s2 = "kernelcache.release."
    $s3 = "Firmware/dfu/"
    $s4 = ".dmg"

  condition:
    uint32be(0) == 0x504B0304 and
    all of them
}
