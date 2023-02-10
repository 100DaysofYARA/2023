import "pe"

rule Failed_Checksum {
	meta:
		description = "Did you know that 83% of malware has invalid checksums and 90% of legitimate files had valid checksums?"
		source = "https://practicalsecurityanalytics.com/pe-checksum/"
	condition:
		pe.checksum != pe.calculate_checksum()

}
