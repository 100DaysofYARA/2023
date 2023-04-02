rule file_sdef
{
  meta:
    description = "Identify Apple scripting dictionary files."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.02"
    reference = "https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/AboutScriptingTerminology.html"
    sample = "11935d4a6ebabc75a45e79d7d3830c47701474b0f34d92937fa32c6eb6a22fcd"
    DaysofYARA = "92/100"

  strings:
    $dtd = "/System/Library/DTDs/sdef.dtd"
    $s0  = "<?xml"
    $s1  = "<dictionary"

  condition:
    all of them
}
