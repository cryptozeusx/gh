# Rule: No Schema Guessing
> **When:** Any GitHub API response field is ambiguous, missing, or in an unexpected format.  
> **Do:** STOP. Do not infer or guess. Ask the user to clarify the expected shape.  
> **Because:** Guessing schema leads to silent data corruption in the output JSON — the hardest class of bug to detect.
