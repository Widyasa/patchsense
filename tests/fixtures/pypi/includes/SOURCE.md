# Requirements includes

Synthetic pins written for the `-r` and `-c` tests. They are not copied from another project.

`requirements.txt` includes `rag/requirements-rag.txt` and `constraints.txt`. `requests` is pinned in both the parent and the included file so the parser can show that the duplicate is kept once.
