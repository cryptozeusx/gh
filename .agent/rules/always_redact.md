# Rule: Always Redact Before Output
> **When:** Any regex match is found in file content.  
> **Do:** Pass the matched string through `_redact_key()` before writing to ANY output (console, JSON, text report).  
> **Because:** A single unredacted key in a research output is a real-world security risk.
