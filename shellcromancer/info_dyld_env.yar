rule info_dyld_env_vars
{
	meta:
		description = "Identify executables with environment variables changing the dynamic loader settings. See `man dyld` or `strings /usr/lib/dyld/ | grep DYLD_`"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.07"
		DaysofYARA = "38/100"

	strings:
		$1 = "DYLD_SHARED_REGION"
		$2 = "DYLD_IN_CACHE"
		$3 = "DYLD_JUST_BUILD_CLOSURE"
		$4 = "DYLD_SHARED_CACHE_DIR"
		$5 = "DYLD_PAGEIN_LINKING"
		$6 = "DYLD_FORCE_PLATFORM"
		$7 = "DYLD_SKIP_MAIN"
		$8 = "DYLD_AMFI_FAKE"
		$9 = "DYLD_PRINT_SEGMENTS"
		$10 = "DYLD_PRINT_LIBRARIES"
		$11 = "DYLD_PRINT_BINDINGS"
		$12 = "DYLD_PRINT_INITIALIZERS"
		$13 = "DYLD_PRINT_APIS"
		$14 = "DYLD_PRINT_NOTIFICATIONS"
		$15 = "DYLD_PRINT_INTERPOSING"
		$16 = "DYLD_PRINT_LOADERS"
		$17 = "DYLD_PRINT_SEARCHING"
		$18 = "DYLD_PRINT_ENV"
		$19 = "DYLD_PRINT_TO_STDERR"
		$20 = "DYLD_PRINT_TO_FILE"
		$21 = "DYLD_LIBRARY_PATH"
		$22 = "DYLD_FRAMEWORK_PATH"
		$23 = "DYLD_FALLBACK_FRAMEWORK_PATH"
		$24 = "DYLD_FALLBACK_LIBRARY_PATH"
		$25 = "DYLD_VERSIONED_FRAMEWORK_PATH"
		$26 = "DYLD_VERSIONED_LIBRARY_PATH"
		$27 = "DYLD_INSERT_LIBRARIES"
		$28 = "DYLD_IMAGE_SUFFIX"
		$29 = "DYLD_ROOT_PATH"
		$30 = "DYLD_CLOSURE_DIR"

	condition:
		any of them
}
