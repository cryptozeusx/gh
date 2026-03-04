# Rule: No Write Operations to GitHub
> **When:** At any point during a scan.  
> **Do:** Never call any GitHub API endpoint that modifies state (POST, PUT, PATCH, DELETE).  
> **Because:** This is a read-only security research tool. A write operation would constitute unauthorized modification of a third-party repository.
