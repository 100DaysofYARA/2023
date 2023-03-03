rule GregsChallengeReductor
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "A reductor rule for Greg's workflow writeup challenge"
        version = "1.0"
        date = "2023-02-24"
        sha256="4e2d038e9d72ee4d660755ba973a31471dda167d1a51bfdfe60abb2b3de78ba1"
    strings:
        $const_1 = { 24 95 73 C2 48 }                                                // 0x48C27395
        $const_2 = { FF FF FF 7F }                                                   // 0x7FFFFFFF
        $pdb_start = "C:\\git_kraken_repo\\reductor-dev" 
        $mtx1 = "Global\\$$wrk_ls"
        $mtx2 = "Global\\$$wrk_ff"
        $mtx3 = "Global\\$$wrk_cr"
    condition:
        for all i in ( 1..#const_1 ) : ( $const_2 in ( @const_1[i]..@const_1[i]+10) ) // Find the two constants next to each other
        or all of ($mtx*) 
        or $pdb_start
        
}