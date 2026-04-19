![[Pasted image 20260419190910.png]]

No real hint, just the file.

Type of file:-

```
catacombs: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=70957f34dad6e320b16a90233b16efe644686655, for GNU/Linux 4.4.0, not stripped
```

Since the file is statically linked, it has a lot of noise and is of a bigger size but since it is also `not stripped` we can start directly at the `main` function.

On running the file to check what it does:-

![[Pasted image 20260419191128.png]]

We see `ACCESS DENIED` which means if the string is correct, we might get something like `ACCESS GRANTED`


###### Analysis in `ghidra`:-

![[Pasted image 20260419191247.png]]

We found the section of the code which prints `ACCESS DENIED` and `ACCESS GRANTED` in the `main` function itself.
The flag is present in plain sight!

Flag - `CIT{3R2rA2J0PdFH}`


