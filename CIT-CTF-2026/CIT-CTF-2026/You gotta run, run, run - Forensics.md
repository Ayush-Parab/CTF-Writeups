![](Pasted%20image%2020260419223715.png)

The challenge file is a `Windows Registry` file. I used `Fred` to open it in Linux.

The black box flashing is definitely the `command prompt` or the `powershell` flashing.
In windows registry, primary location for persistence for running items is
`Software\Microsoft\Windows\CurrentVersion\Run`

We navigate here using `Fred`

![](Pasted%20image%2020260419224017.png)

OneDrive looks fine but take a look at `AzureTenant`...
It is executing an `.exe` file called `fj3493.exe` which is definitely not normal.

Hence, the name is our flag!

Flag - `CIT{AzureTenant}`

