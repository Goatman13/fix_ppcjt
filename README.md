# fix_ppcjt
Plugin tries to find and fix PowerPC jump tables in IDA disassembly. Yes, it's 2025 and we still need stuff like that for PPC64.

Copy .py file into ida plugins directory, Press Alt + Shift + 5 to Fix all PPC jump tables.  
You can also fix single table by clicking on bctr opcode and pressing Alt + Shift + 4.  
Sometimes IDA decides to not detect every table, running plugin again fixes it. No idea why...  
Plugin requires pre-analyzed database, and correctly set r2 register. All that because it is supposed to fix jump tables, not create them.  
Works with IDA 7.5 and IDA 9.0, maybe others.

![a](https://github.com/user-attachments/assets/976cbf05-6a90-4e5c-941c-49d0e7f7a4de)
