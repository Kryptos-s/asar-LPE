# asar-lpe

A Windows Discord ASAR LPE proof of concept.

It finds signed stable, PTB, and Canary Discord installations or any other Electron app, installs a fixed proof payload in `app.asar`, uses Discord for the UAC prompt, restores the original archive, and opens a persistent elevated Command Prompt. With this u can trick users into accepting UAC prompts that are from legit signed apps but they actually elevate your payload.

```
discord-lpe-poc.exe scan  
discord-lpe-poc.exe prove \<index\> --authorized  
discord-lpe-poc.exe restore
```

For educational and authorized security research only. Use it only on systems you own or have explicit permission to test.

