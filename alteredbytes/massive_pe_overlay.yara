import "pe"
import "math"

rule massive_pe_overlay {

meta:
  description = "Check PE files for overlays that make up more than X% of the total filesize and have an entropy below 1"
  author = "Jeremy Brown with some syntax inspiration by Greg Lesnewich"
  date = "2023-01-18"
  version = "1.0"
  reference = "https://forensicitguy.github.io/pecheck-malware-weight-loss/"
  reference = "https://forensicitguy.github.io/malware-weight-loss-fast-foremost/"

condition:

// check for PE
	uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and

// make sure PE overlay is present
	pe.overlay.offset != 0x0 and

// check if overlay is more than X% of total filesize
	(pe.overlay.size) > (filesize * 0.90) and

// check for a lack of PE signature
	pe.number_of_signatures == 0 and

// check for low entropy within PE overlay
	math.entropy(pe.overlay.offset,pe.overlay.size) <= 1
}
