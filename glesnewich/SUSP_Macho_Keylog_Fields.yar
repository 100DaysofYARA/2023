rule SUSP_Macho_Keylog_Fields
{
	meta:
		author = "Greg Lesnewich"
		description = "specialized key strokes can be recorded with brackets around them in some MacOS samples - lets mine some!"
		date = "2023-02-03"
		version = "1.0"

	strings:
    	        $asterisk_keylog = "[asterisk]" ascii wide
    	        $caps_keylog = "[caps]" ascii wide
    	        $clear_keylog = "[clear]" ascii wide
    	        $decimal_keylog = "[decimal]" ascii wide
    	        $del_keylog = "[del]" ascii wide
    	        $divide_keylog = "[divide]" ascii wide
    	        $down_keylog = "[down]" ascii wide
    	        $end_keylog = "[end]" ascii wide
    	        $enter_keylog = "[enter]" ascii wide
    	        $equals_keylog = "[equals]" ascii wide
    	        $esc_keylog = "[esc]" ascii wide
    	        $f1_keylog = "[f1]" ascii wide
    	        $f10_keylog = "[f10]" ascii wide
    	        $f11_keylog = "[f11]" ascii wide
    	        $f12_keylog = "[f12]" ascii wide
    	        $f13_keylog = "[f13]" ascii wide
    	        $f14_keylog = "[f14]" ascii wide
    	        $f15_keylog = "[f15]" ascii wide
    	        $f16_keylog = "[f16]" ascii wide
    	        $f17_keylog = "[f17]" ascii wide
    	        $f18_keylog = "[f18]" ascii wide
    	        $f19_keylog = "[f19]" ascii wide
    	        $f2_keylog = "[f2]" ascii wide
    	        $f20_keylog = "[f20]" ascii wide
    	        $f3_keylog = "[f3]" ascii wide
    	        $f4_keylog = "[f4]" ascii wide
    	        $f5_keylog = "[f5]" ascii wide
    	        $f6_keylog = "[f6]" ascii wide
    	        $f7_keylog = "[f7]" ascii wide
    	        $f8_keylog = "[f8]" ascii wide
    	        $f9_keylog = "[f9]" ascii wide
    	        $fn_keylog = "[fn]" ascii wide
    	        $fwddel_keylog = "[fwddel]" ascii wide
    	        $help_keylog = "[help]" ascii wide
    	        $home_keylog = "[home]" ascii wide
    	        $hyphen_keylog = "[hyphen]" ascii wide
    	        $left_cmd_keylog = "[left-cmd]" ascii wide
    	        $left_ctrl_keylog = "[left-ctrl]" ascii wide
    	        $left_keylog = "[left]" ascii wide
    	        $left_option_keylog = "[left-option]" ascii wide
    	        $left_shift_keylog = "[left-shift]" ascii wide
    	        $mute_keylog = "[mute]" ascii wide
    	        $pgdown_keylog = "[pgdown]" ascii wide
    	        $pgup_keylog = "[pgup]" ascii wide
    	        $plus_keylog = "[plus]" ascii wide
    	        $return_keylog = "[return]" ascii wide
    	        $right_cmd_keylog = "[right-cmd]" ascii wide
    	        $right_ctrl_keylog = "[right-ctrl]" ascii wide
    	        $right_keylog = "[right]" ascii wide
    	        $right_option_keylog = "[right-option]" ascii wide
    	        $right_shift_keylog = "[right-shift]" ascii wide
    	        $tab_keylog = "[tab]" ascii wide
    	        $unknown_keylog = "[unknown]" ascii wide
    	        $up_keylog = "[up]" ascii wide
    	        $voldown_keylog = "[voldown]" ascii wide
    	        $volup_keylog = "[volup]" ascii wide
	condition:
        	(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	8 of them
}
