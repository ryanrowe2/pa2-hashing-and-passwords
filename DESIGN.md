# DESIGN.md

### Design Questions

1. Other Ways to Vary a Password

   Real password crackers often try more variations than simply uppercasing or lowercasing individual characters. One common method is Leet Speak Substitution (also known as "1337 speak"), which involves replacing letters with visually similar numbers or symbols. For example, 'a' is replaced with '4', 'e' with '3', 'i' with '1', 'o' with '0', 's' with '5', and 't' with '7'. To implement this in our program, we would create a mapping of letters to their leet equivalents. The program would then iterate through the password, generating variations by substituting each character with its corresponding leet character, one at a time. For each variation, the program would compute the hash and compare it to the given hash. After checking each substitution, the original character would be restored before moving to the next position in the password. This method allows for a significant increase in password variations while remaining computationally feasible.

   Another effective approach is using common prefixes and suffixes. Users frequently add these to their passwords for memorability or to meet password length or complexity requirements. Examples of common prefixes include '!@#', '123', and 'qwerty', while common suffixes might be '1', '!', '2021', or 'abc'. To integrate this method, we would first define a list of common prefixes and suffixes. The program would generate variations by prepending each prefix and appending each suffix to the original password. Each variation would then be hashed and compared to the target hash. To increase coverage, we could even combine prefixes and suffixes, creating further variations. This method is especially useful for targeting users who modify simple, easily guessable passwords by adding extra characters.

2. Working Memory and Limitations

   The amount of working memory required for this password cracker is relatively small. First, we need memory for storing the password itself, with a maximum length of 1023 characters, which requires 1024 bytes of storage. We also need to store a copy of the original password, which requires another 1024 bytes. In addition to password storage, we need memory for the 32-byte given_hash (the hash we are trying to match) and a 32-byte computed_hash to hold the result of each hash calculation. Temporary variables, such as loop counters and character buffers, also occupy some memory, but their impact is minimal. Altogether, the estimated memory usage for each process is around 3 kilobytes, which is quite small by modern standards.

   Given the relatively low memory requirements, the primary limitation of this password cracker is not memory but processing speed. Computing SHA256 hashes is computationally intensive, and when we are checking millions of potential passwords, the program becomes more limited by how quickly it can process and hash these inputs. Each password and its variations need to be hashed and compared, which introduces significant computational overhead. Therefore, the performance bottleneck is primarily in the time it takes to compute and compare hashes, rather than the amount of memory being used. To optimize performance, one could implement multi-threading or parallel processing to check multiple passwords concurrently. Additionally, reducing redundant computations and employing more efficient algorithms could further improve the overall speed of the password cracker.