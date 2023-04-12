rule lang_python_bytecode
{
  meta:
    description = "Identify Python compiled bytecode"
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.27"
    reference = "https://nedbatchelder.com/blog/200804/the_structure_of_pyc_files.html"
    DaysofYARA = "86/100"

  condition:
    uint32be(0) == 0x420D0D0A
}
