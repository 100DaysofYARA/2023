rule INFO_MacOS_NamedPipe_mkfifo
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for mkfifo command used to create a MacOS named pipe"

	strings:
		$ = "mkfifo" ascii wide
	condition:
		all of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSXPC
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for references to XPC, MacOS low-level interprocess communications, via the NSXPCConnection API classes"

	strings:
		$ = "NSXPCConnection" ascii wide
		$ = "NSXPCInterface" ascii wide
		$ = "NSXPCListener" ascii wide
		$ = "NSXPCListenerEndpoint" ascii wide
	condition:
		any of them
}

rule INFO_MacOS_NamedPipe_ObjC_XPC_API
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for references to XPC, MacOS low-level interprocess communications, via the XPC APIs"

	strings:
		$ = "IOSurfaceLookupFromXPCObject" ascii wide
		$ = "IOSurfaceCreateXPCObject" ascii wide
	condition:
		any of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSPipe
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for ObjectiveC interface NSPipe"

	strings:
		$ = "$_NSPipe" ascii wide
		$ = "NSPipe" ascii wide
	condition:
		any of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSConnection
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for deprecated ObjectiveC interface NSConnection, used in distributed objects mechanism, often to vend an object to other applications"

	strings:
		$ = "NSConnection" ascii wide
	condition:
		any of them
}


rule INFO_MacOS_NamedPipe_ObjC_NSXPC
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for references to XPC, MacOS low-level interprocess communications, via the NSXPCConnection API classes"

	strings:
		$ = "NSXPCConnection" ascii wide
		$ = "NSXPCInterface" ascii wide
		$ = "NSXPCListener" ascii wide
		$ = "NSXPCListenerEndpoint" ascii wide
	condition:
		any of them
}

rule INFO_MacOS_NamedPipe_ObjC_XPC_API
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-28"
		version = "1.0"
		description = "check for references to XPC, MacOS low-level interprocess communications, via the XPC APIs"

	strings:
		$ = "IOSurfaceLookupFromXPCObject" ascii wide
		$ = "IOSurfaceCreateXPCObject" ascii wide
	condition:
		any of them
}
