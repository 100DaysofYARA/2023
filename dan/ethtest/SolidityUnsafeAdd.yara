rule SolidityUnsafeAdd
{
    strings:
        // https://leftasexercise.com/2021/09/05/a-deep-dive-into-solidity-contract-creation-and-the-init-code/#:~:text=big%20endian%20notation.-,The%20init%20bytecode,-Armed%20with%20this
        $sol_mempointer_alloc = { 
            60 80   // PUSH1 0x80
            60 40   // PUSH1 0x40
            52      // MSTORE
            }    
        $add_ballance = { 
            54      // SLOAD	
            01      // ADD	
            92      // SWAP3	
            50      // POP	
            50      // POP	
            81      // DUP2	
            90      // SWAP1	
            55      // SSTORE	
         }
         $require_no_overflow = {
            01      // ADD
            10      // LT
	        15      // ISZERO
	        15      // ISZERO
	        15      // ISZERO
	        60      // PUSH1 0x9b

         }

    condition:
        $sol_mempointer_alloc at 0 and 
        not $require_no_overflow in ( @add_ballance-30..@add_ballance )
}